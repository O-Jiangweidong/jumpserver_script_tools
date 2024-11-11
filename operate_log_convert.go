package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

func ConvertBeforeAfterToDiff(before, after map[string]interface{}) map[string]string {
	diff := make(map[string]string)
	keys := make(map[string]struct{})
	for k := range before {
		keys[k] = struct{}{}
	}
	for k := range after {
		keys[k] = struct{}{}
	}

	for k := range keys {
		var beforeValue, afterValue string
		if val, ok := before[k]; ok {
			beforeValue = fmt.Sprintf("%v", val)
		}
		if val, ok := after[k]; ok {
			afterValue = fmt.Sprintf("%v", val)
		}
		diff[k] = beforeValue + "\x00" + afterValue
	}

	return diff
}

func Do() {
	host := flag.String("h", "localhost", "主机名或IP地址")
	port := flag.Int("p", 3306, "主机端口")
	username := flag.String("u", "root", "用户名")
	password := flag.String("P", "", "密码")
	database := flag.String("d", "", "数据库名")
	workers := flag.Int("w", 3, "工人数量")
	workload := flag.Int("l", 1000, "每次工人处理的条数")
	index := flag.Int("i", 0, "任务从第几条开始")

	flag.Parse()

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%v)/%s", *username, *password, *host, *port, *database)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("连接数据库失败: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("连接数据库失败: %v", err)
	}

	db.SetConnMaxLifetime(time.Minute * 5)
	db.SetMaxIdleConns(10)
	db.SetMaxOpenConns(100)

	batchSize := *workload
	offset := *index
	var mutex sync.Mutex

	fmt.Println("【INFO】我开始搞了")
	// 先获取总记录数
	startTime := time.Now()
	var totalRecords int
	err = db.QueryRow("SELECT COUNT(*) FROM audits_operatelog").Scan(&totalRecords)
	if err != nil {
		log.Fatalf("获取总记录数失败: %v", err)
	}
	fmt.Printf("【INFO】总记录数: %d\n", totalRecords)

	fmt.Printf("【INFO】开始给表增加 diff 字段\n")
	_, _ = db.Exec("ALTER TABLE audits_operatelog ADD COLUMN diff JSON")

	_, err = db.Exec("SELECT diff FROM audits_operatelog LIMIT 1")
	if err != nil {
		log.Fatalf("【ERROR】diff 字段看样子是有点问题，你自己手动增加吧，%v", err)
	}

	// 进度 channel
	progressChan := make(chan int, *workers)
	var wg sync.WaitGroup
	fmt.Printf("【INFO】我开始准备 %v 个工人搞事情\n", *workers)
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for {
				subStartTime := time.Now()
				mutex.Lock()
				currentOffset := offset
				modifyOffset := offset + batchSize
				offset = modifyOffset
				mutex.Unlock()

				idList, beforeList, afterList, err := queryBatch(db, batchSize, currentOffset)
				if err != nil {
					log.Fatalf("【ERROR】批量查询失败: %v", err)
				}

				if len(idList) == 0 {
					break
				}

				err = processBatch(db, idList, beforeList, afterList)
				if err != nil {
					log.Fatalf("【ERROR】批量更新操作日志失败: %v", err)
				}

				progress := float64(currentOffset) / float64(totalRecords) * 100
				elapsedTime := time.Since(subStartTime).Seconds()
				totalTime := time.Since(startTime).Seconds()
				fmt.Printf("【INFO】%d 号工人搞完了 %d - %d 的记录，花费 %.2f 秒，总用时: %.2f 秒，总进度: %.2f%%\n", workerID, currentOffset, modifyOffset, elapsedTime, totalTime, progress)
			}
		}(i)
	}

	wg.Wait()
	close(progressChan)

	err = taskAfterModifyDBColumn(db)
	if err != nil {
		log.Fatalf("【ERROR】搞出来一个错误: %v", err)
	}
	fmt.Println("【OK】任务执行成功")
}

func taskAfterModifyDBColumn(db *sql.DB) error {
	_, err := db.Exec("ALTER TABLE audits_operatelog ADD COLUMN IF NOT EXISTS resource_id VARCHAR(128) NOT NULL")
	if err != nil {
		fmt.Printf("增加 resource_id 失败，自己检查吧: %v\n", err)
	}

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM audits_operatelog WHERE JSON_EXTRACT(`diff`, '$') IS NULL").Scan(&count)
	if err != nil {
		return fmt.Errorf("查询 diff 字段为空的记录数量失败: %v", err)
	}
	if count > 0 {
		return fmt.Errorf("字段 diff 为空: %v，大于 0，请检查后手动删除 before 和 after 字段 %v", count)
	}

	_, err = db.Exec("ALTER TABLE audits_operatelog DROP COLUMN `before`, DROP COLUMN `after`;")
	if err != nil {
		return fmt.Errorf("删除 before, after 字段失败: %v", err)
	}
	fmt.Println("【OK】成功删除 before 和 after 字段")
	return nil
}

func queryBatch(db *sql.DB, limit, offset int) ([]string, []string, []string, error) {
	selectSQL := "SELECT id, COALESCE(`before`, '{}'), COALESCE(`after`, '{}') FROM audits_operatelog LIMIT %d OFFSET %d"
	query := fmt.Sprintf(selectSQL, limit, offset)
	rows, err := db.Query(query)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("查询操作日志失败: %v", err)
	}
	defer rows.Close()

	var idList, beforeList, afterList []string
	for rows.Next() {
		var id, beforeJSON, afterJSON string
		err = rows.Scan(&id, &beforeJSON, &afterJSON)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("获取 before 和 after 字段内容失败: %v", err)
		}

		idList = append(idList, id)
		beforeList = append(beforeList, beforeJSON)
		afterList = append(afterList, afterJSON)
	}

	if err = rows.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("操作数据库失败: %v", err)
	}

	return idList, beforeList, afterList, nil
}

func processBatch(db *sql.DB, idList, beforeList, afterList []string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("事务开始失败: %v", err)
	}

	updateStmt, err := tx.Prepare("UPDATE audits_operatelog SET diff = ? WHERE id = ?")
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("创建更新 SQL 语句失败: %v", err)
	}
	defer updateStmt.Close()

	for i := range idList {
		var before, after map[string]interface{}
		if err = json.Unmarshal([]byte(beforeList[i]), &before); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("格式化 before 字段失败: %v", err)
		}
		if err = json.Unmarshal([]byte(afterList[i]), &after); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("格式化 after 字段失败: %v", err)
		}

		diff := ConvertBeforeAfterToDiff(before, after)

		diffJSON, err := json.Marshal(diff)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("格式化 diff 字段失败: %v", err)
		}

		_, err = updateStmt.Exec(string(diffJSON), idList[i])
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("更新 diff 字段失败: %v", err)
		}
	}

	if err = tx.Commit(); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("事务提交失败: %v", err)
	}

	return nil
}

func main() {
	Do()
}
