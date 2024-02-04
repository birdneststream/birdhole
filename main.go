package main

import (
	"fmt"
	"log"
	"net/http"

	"git.mills.io/prologic/bitcask"
)

type FileInfo struct {
	Name        string `json:"name"`
	Width       int    `json:"width"`
	Height      int    `json:"height"`
	Size        int64  `json:"size"`
	MimeType    string `json:"mime_type"`
	Extension   string `json:"extension"`
	Timestamp   int64  `json:"timestamp"`
	KeyExpiry   int64  `json:"key_expiry"`
	Description string `json:"description"`
	Views       int    `json:"views"`
}

var birdBase *bitcask.Bitcask

var config Config

func main() {
	loadConfig()

	// Print welcome screen
	fmt.Println("Birdhole!")

	// POST end point used only to upload files, requires upload key
	http.HandleFunc("/hole", galleryUpload)

	// View gallery photos, requires gallery key
	http.HandleFunc("/gallery", galleryRequest)

	// Admin only delete
	http.HandleFunc("/delete", galleryDelete)

	// Load a single file
	http.HandleFunc("/", galleryFile)

	// Start the async function to check every so often for expired files to delete
	go checkExpiry()

	// Web service
	log.Fatal(http.ListenAndServe(config.Listen+":"+config.Port, nil))
}
