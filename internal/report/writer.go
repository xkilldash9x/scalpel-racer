// FILENAME: internal/report/writer.go
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/xkilldash9x/scalpel-racer/internal/models"
)

// Writer handles artifact generation.
type Writer struct {
	BaseDir string
}

func NewWriter(baseDir string) *Writer {
	return &Writer{BaseDir: baseDir}
}

// WriteArtifacts saves the scan results to disk in structured formats.
func (w *Writer) WriteArtifacts(results []models.ScanResult, prefix string) error {
	if err := os.MkdirAll(w.BaseDir, 0755); err != nil {
		return err
	}

	timestamp := time.Now().Format("20060102-150405")
	baseName := fmt.Sprintf("%s-%s", prefix, timestamp)

	// 1. JSON Report
	jsonPath := filepath.Join(w.BaseDir, baseName+".json")
	if err := w.writeJSON(results, jsonPath); err != nil {
		return err
	}

	// 2. CSV Report
	csvPath := filepath.Join(w.BaseDir, baseName+".csv")
	if err := w.writeCSV(results, csvPath); err != nil {
		return err
	}

	return nil
}

func (w *Writer) writeJSON(results []models.ScanResult, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func (w *Writer) writeCSV(results []models.ScanResult, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	cw := csv.NewWriter(f)
	defer cw.Flush()

	// Header
	header := []string{"Index", "Status", "Duration(ns)", "Hash", "Error"}
	if err := cw.Write(header); err != nil {
		return err
	}

	// Rows
	for _, r := range results {
		errStr := ""
		if r.Error != nil {
			errStr = r.Error.Error()
		}
		row := []string{
			strconv.Itoa(r.Index),
			strconv.Itoa(r.StatusCode),
			strconv.FormatInt(r.Duration.Nanoseconds(), 10),
			r.BodyHash,
			errStr,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}

	return nil
}
