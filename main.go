package main

import (
	"encoding/json"
	"fmt"
	"image"
	"io"
	"log"
	"math/rand"
	"mime/multipart"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"git.mills.io/prologic/bitcask"
	"github.com/BurntSushi/toml"
	"github.com/gabriel-vasile/mimetype"
	"github.com/hako/durafmt"
)

// function to generate random filename from alphanum
func generateRandomFilename(urlLen int, extension string) string {
	var alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, urlLen)
	for i := range bytes {
		bytes[i] = alphanum[rand.Intn(len(alphanum))]
	}
	return string(bytes) + extension
}

type FileInfo struct {
	Name        string `json:"name"`
	Width       int    `json:"width"`
	Height      int    `json:"height"`
	Size        int64  `json:"size"`
	MimeType    string `json:"mime_type"`
	Extension   string `json:"extension"`
	KeyExpiry   int64  `json:"key_expiry"`
	Description string `json:"description"`
}

func handlePostRequest(w http.ResponseWriter, r *http.Request) {
	// check if header value contains X-Auth-Token and it is set
	if r.Header.Get("X-Auth-Token") != config.Key {
		http.NotFound(w, r)
		return
	}

	// if not POST request
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	urlLenInt := config.UrlLen
	if r.FormValue("url_len") != "" {
		urlLen := r.FormValue("url_len")
		// convert urlLen to int
		urlLenInt, _ = strconv.Atoi(urlLen)
	}

	expiryInt := config.Expiry
	if r.FormValue("expiry") != "" {
		expiry := r.FormValue("expiry")
		// convert expiry to int64
		expiryInt, _ = strconv.ParseInt(expiry, 10, 64)
	}

	// description, if the length is over 2048 trim it
	description := r.FormValue("description")
	if len(description) > 2048 {
		description = description[:2048]
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// if file is larger than 1024mb return error
	if r.ContentLength > 1024*1024*1024 {
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}

	// determine file extension or mime type
	fileType, err := mimetype.DetectReader(file)
	if err != nil {
		w.Write([]byte("error detecting the mime type of your file\n"))
		return
	}

	fileName := generateRandomFilename(urlLenInt, fileType.Extension())

	fileInfo := FileInfo{
		Name:        fileName,
		Size:        r.ContentLength,
		MimeType:    fileType.String(),
		Extension:   fileType.Extension(),
		KeyExpiry:   time.Now().Unix() + expiryInt,
		Description: description,
		Width:       0,
		Height:      0,
	}

	putFile(fileInfo, file, w)

	// return url with config.Host
	fmt.Fprintf(w, "%s/%s", "https://"+config.Host, fileName)
}

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

	// If the file is an image, get its dimensions
	if strings.HasPrefix(fileInfo.MimeType, "image/") {
		image, _, err := image.DecodeConfig(f)
		if err != nil {
			http.Error(w, "ERR"+err.Error(), http.StatusInternalServerError)
			return
		}

		fileInfo.Width = image.Width
		fileInfo.Height = image.Height
	}

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
	if !birdBase.Has([]byte(key)) {
		log.Println("Key not found: " + key)
		return
	}

	err := birdBase.Delete([]byte(key))
	if err != nil {
		log.Fatal(err)
	}

	// delete the file from images
	err = os.Remove(config.FilePath + key)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Deleted key: " + string(key))
}

var birdBase *bitcask.Bitcask

var config Config

func loadConfig() {
	// print loading config.toml
	fmt.Println("Loading config.toml")
	_, err := toml.DecodeFile("config.toml", &config)
	if err != nil {
		fmt.Println("Error in config.toml")
		fmt.Println(err)
		os.Exit(1)
	}
}

func main() {
	loadConfig()

	// Append a forward slash at the end if it doesn't already exist
	if config.FilePath[len(config.FilePath)-1:] != "/" {
		config.FilePath = config.FilePath + "/"
	}

	// Print welcome screen
	fmt.Println("Birdhole!")

	var err error
	birdBase, err = bitcask.Open("bird.db")
	if err != nil {
		log.Fatal(err)
	}

	// if folder images does not exist create it
	if _, err := os.Stat(config.FilePath); os.IsNotExist(err) {
		os.Mkdir(config.FilePath, 0755)
	}

	http.HandleFunc("/hole", handlePostRequest)

	http.HandleFunc("/gallery", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.NotFound(w, r)
			return
		}

		// if the param has key = config.Key
		if r.URL.Query().Get("key") != config.GalleryKey && r.URL.Query().Get("key") != config.AdminGalleryKey {
			http.NotFound(w, r)
			return
		}

		isAdmin := r.URL.Query().Get("key") == config.AdminGalleryKey

		// return html with all images
		fmt.Fprintf(w, galleryHtml(isAdmin))

	})

	http.HandleFunc("/delete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.NotFound(w, r)
			return
		}

		// get the key from the url
		key := r.URL.Query().Get("delete")

		// delete the key from bird.db
		deleteFile(key)

		// redirect to gallery with key
		http.Redirect(w, r, "/gallery?key="+config.AdminGalleryKey, http.StatusSeeOther)
	})

	// return image file from images
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.NotFound(w, r)
			return
		}

		// Return 404 if it's not an image request
		validPath := regexp.MustCompile(`^/[a-zA-Z0-9]+\.[a-zA-Z]{3,4}$`)
		if !validPath.MatchString(r.URL.Path) {
			http.NotFound(w, r)
			return
		}

		http.ServeFile(w, r, config.FilePath+r.URL.Path[1:])

	})

	go checkExpiry()

	log.Fatal(http.ListenAndServe(config.Listen+":"+config.Port, nil))
}

type KeyExpiry struct {
	Key        string
	ExpiryTime int64
}

func galleryHtml(isAdmin bool) string {
	// html start string
	html := `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Birdhole</title>
        <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.16/dist/tailwind.min.css" rel="stylesheet">
    </head>
    <body class="bg-gray-100">
        <div class="container mx-auto px-4 sm:px-6 lg:px-8">
            <h1 class="text-4xl my-8 text-center">Birdhole</h1>
            <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
    `

	// Store keys and their expiry times in a slice
	var filesInfo []FileInfo
	for key := range birdBase.Keys() {
		valueStr, err := birdBase.Get(key)
		if err != nil {
			log.Fatal(err)
		}

		// Deserialize the JSON data into a FileInfo struct
		var fileInfo FileInfo
		err = json.Unmarshal(valueStr, &fileInfo)
		if err != nil {
			log.Fatal(err)
		}

		filesInfo = append(filesInfo, fileInfo)
	}

	// Sort the slice by expiry time
	sort.Slice(filesInfo, func(i, j int) bool {
		return filesInfo[i].KeyExpiry > filesInfo[j].KeyExpiry
	})

	// Generate HTML
	for _, fileInfo := range filesInfo {
		duration := durafmt.Parse(time.Second * time.Duration(fileInfo.KeyExpiry-time.Now().Unix()))

		html += fmt.Sprintf(`
			<div class="border rounded-lg overflow-hidden">
				<a href="https://%s/%s" target="_blank">
					<img class="w-full h-96 object-contain" src="https://%s/%s" alt="%s">
				</a>
				<div class="p-4">
					<h2 class="font-bold mb-2">%s</h2>
					<p class="text-gray-700">%s</p>
					<p class="text-sm text-gray-500">Expires: %s</p>
					<p class="text-sm text-gray-500">Size: %.2f KB</p>
					<p class="text-sm text-gray-500">Dimensions: %dx%d</p>
		`, config.Host, fileInfo.Name, config.Host, fileInfo.Name, fileInfo.Name, fileInfo.Name, fileInfo.Description, duration, float64(fileInfo.Size)/1024.0, fileInfo.Width, fileInfo.Height)

		if isAdmin {
			html += fmt.Sprintf(`
					<a href="https://%s/delete?delete=%s&key=%s" class="mt-2 bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded inline-block">
						Delete
					</a>`,
				config.Host, fileInfo.Name, config.AdminGalleryKey)
		}

		html += `
				</div>
			</div>`
	}

	html += `
			</div>
		</div>
	</body>
	</html>
	`

	// minify html
	html = strings.ReplaceAll(html, "\n", "")
	html = strings.ReplaceAll(html, "\t", "")
	html = strings.ReplaceAll(html, "  ", "")

	return html
}
