package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"git.mills.io/prologic/bitcask"
	"github.com/BurntSushi/toml"
)

func putFile(fileInfo FileInfo, file multipart.File, w http.ResponseWriter) {
	// if folder images does not exist create it
	if _, err := os.Stat(config.FilePath); os.IsNotExist(err) {
		os.Mkdir(config.FilePath, 0755)
	}

	f, err := os.OpenFile(config.FilePath+"/"+fileInfo.Name, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	file.Seek(0, 0)
	io.Copy(f, file)

	fileInfoJson, err := json.Marshal(fileInfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = birdBase.Put([]byte(fileInfo.Name), fileInfoJson)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func checkExpiry() {
	for {
		var wg sync.WaitGroup

		for key := range birdBase.Keys() {
			wg.Add(1)
			go func(key []byte) {
				defer wg.Done()

				valueStr, err := birdBase.Get(key)
				if err != nil {
					log.Fatal(err)
				}

				var fileInfo FileInfo
				err = json.Unmarshal(valueStr, &fileInfo)
				if err != nil {
					log.Fatal(err)
				}

				if time.Now().Unix() > fileInfo.KeyExpiry {
					deleteFile(string(key))
				}
			}(key)
		}

		wg.Wait()
		time.Sleep(1 * time.Minute)
	}
}

func deleteFile(key string) {
	// Verify integrity before attempting to delete
	if _, err := os.Stat(config.FilePath + key); os.IsNotExist(err) {
		log.Println("WARN: File not found, will remove key from db: " + key)
	}

	// No file, no key, there is nothing to delete.
	if !birdBase.Has([]byte(key)) {
		log.Println("Key not found: " + key)
		return
	}

	// Delete the file from database
	err := birdBase.Delete([]byte(key))
	if err != nil {
		log.Fatal(err)
	}

	// Delete the file from disk
	err = os.Remove(config.FilePath + key)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Deleted key: " + string(key))
}

// Random filename generator for uploaded files
func generateRandomFilename(urlLen int, extension string) string {
	var alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, urlLen)
	for i := range bytes {
		bytes[i] = alphanum[rand.Intn(len(alphanum))]
	}
	return string(bytes) + extension
}

// Load the config file and verify integrity, then load database
func loadConfig() {
	// print loading config.toml
	fmt.Println("Loading config.toml")
	_, err := toml.DecodeFile("config.toml", &config)
	if err != nil {
		fmt.Println("Error in config.toml")
		fmt.Println(err)
		os.Exit(1)
	}

	// Append a forward slash at the end if it doesn't already exist
	if config.FilePath[len(config.FilePath)-1:] != "/" {
		config.FilePath = config.FilePath + "/"
	}

	// if folder images does not exist create it
	if _, err := os.Stat(config.FilePath); os.IsNotExist(err) {
		os.Mkdir(config.FilePath, 0755)
	}

	birdBase, err = bitcask.Open("bird.db")
	if err != nil {
		log.Fatal(err)
	}
}

func cleanString(str string) string {
	// Prevent XSS hopefully
	allowedChars := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz .():,;!?-_"

	var filteredDescription strings.Builder
	for _, ch := range str {
		if strings.ContainsRune(allowedChars, ch) {
			filteredDescription.WriteRune(ch)
		}
	}
	str = filteredDescription.String()

	return str
}
