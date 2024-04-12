package sequencesender

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/0xPolygonHermez/zkevm-sequence-sender/log"
	"github.com/ethereum/go-ethereum/common"
)

// Synchronizer represents a synchronizer local file storage
type Synchronizer struct {
	FileName     string
	entries      map[uint64]*SyncEntry
	mutexEntries sync.Mutex
	latestId     uint64
}

// SyncEntry represents an entry of the sync file
type SyncEntry struct {
	SentTimestamp time.Time   `json:"sentTimestamp"`
	AccInputHash  common.Hash `json:"accInputHash"`
	FromBatch     uint64      `json:"fromBatch"`
	ToBatch       uint64      `json:"toBatch"`
}

// NewSynchronizer inits the synchronizer
func NewSynchronizer(fileName string) (*Synchronizer, error) {
	sync := &Synchronizer{
		FileName: fileName,
		entries:  make(map[uint64]*SyncEntry),
	}

	err := sync.restoreFromFile()
	if err != nil {
		return nil, err
	}
	return sync, nil
}

// restoreFromFile loads and restores entries from the file
func (s *Synchronizer) restoreFromFile() error {
	// Check if file exists
	if _, err := os.Stat(s.FileName); os.IsNotExist(err) {
		log.Errorf("file not found %s: %v", s.FileName, err)
		return err
	} else if err != nil {
		log.Errorf("error opening file %s: %v", s.FileName, err)
		return err
	}

	// Read file
	data, err := os.ReadFile(s.FileName)
	if err != nil {
		log.Errorf("error reading file %s: %v", s.FileName, err)
		return err
	}

	// Data unmarshal
	s.mutexEntries.Lock()
	err = json.Unmarshal(data, &s.entries)
	s.mutexEntries.Unlock()
	if err != nil {
		log.Errorf("error decoding data from %s: %v", s.FileName, err)
		return err
	}

	// Locate the latest entry
	var latestId uint64
	for id := range s.entries {
		if id > latestId {
			latestId = id
		}
	}

	s.mutexEntries.Lock()
	s.latestId = latestId
	s.mutexEntries.Unlock()
	return nil
}

// GetLatestEntry returns the latest entry in the sync file
func (s *Synchronizer) GetLatestEntry() *SyncEntry {
	if s.latestId > 0 {
		return s.entries[s.latestId]
	} else {
		return nil
	}
}

// AddEntry adds a new entry to the synchronizer
func (s *Synchronizer) AddEntry(e SyncEntry) error {
	// Add new entry
	s.mutexEntries.Lock()
	s.latestId++
	s.entries[s.latestId] = &e
	s.mutexEntries.Unlock()

	// Save entry persistently
	err := s.saveEntries()
	if err != nil {
		return err
	}
	return nil
}

// saveEntries saves the entries to the sync file
func (s *Synchronizer) saveEntries() error {
	// Create a new temporary file
	fileName := s.FileName[0:strings.IndexRune(s.FileName, '.')] + ".tmp"
	file, err := os.Create(fileName)
	if err != nil {
		log.Errorf("error creating file %s: %v", fileName, err)
		return err
	}
	defer file.Close()

	// Write data
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	s.mutexEntries.Lock()
	err = encoder.Encode(s.entries)
	s.mutexEntries.Unlock()
	if err != nil {
		log.Errorf("error writing file %s: %v", fileName, err)
		return err
	}

	// Rename the temporary file to the original name
	err = os.Rename(fileName, s.FileName)
	if err != nil {
		log.Errorf("error renaming file %s to %s: %v", fileName, s.FileName, err)
		return err
	}

	return nil
}
