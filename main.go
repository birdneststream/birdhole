package main

import (
	"fmt"
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

	urlLen := r.FormValue("url_len")
	// convert urlLen to int
	urlLenInt, err := strconv.Atoi(urlLen)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	expiry := r.FormValue("expiry")
	// convert expiry to int64
	expiryInt, err := strconv.ParseInt(expiry, 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
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

	putKey(fileName, expiryInt, description, w)
	putFile(fileName, file, w)

	// return url with config.Host
	fmt.Fprintf(w, "%s/%s", "https://"+config.Host, fileName)

}

func putKey(fileName string, expiryInt int64, description string, w http.ResponseWriter) {
	// save urlLen, expiry, and fileBytes to bird.db
	key := fileName
	expiryTime := time.Now().Unix() + expiryInt
	expiryStr := strconv.FormatInt(expiryTime, 10)

	err := birdBase.Put([]byte(key), []byte(expiryStr+"\n\r"+description))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
}

func putFile(fileName string, file multipart.File, w http.ResponseWriter) {
	// if folder images does not exist create it
	if _, err := os.Stat(config.FilePath); os.IsNotExist(err) {
		os.Mkdir(config.FilePath, 0755)
	}

	f, err := os.OpenFile(config.FilePath+"/"+fileName, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	file.Seek(0, 0)
	io.Copy(f, file)

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

				expiryTime := strings.Split(string(valueStr), "\n\r")[0]

				value, err := strconv.ParseInt(string(expiryTime), 10, 64)
				if err != nil {
					log.Fatal(err)
				}

				if time.Now().Unix() > value {
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
	var keysExpiry []KeyExpiry
	for key := range birdBase.Keys() {
		valueStr, err := birdBase.Get(key)
		if err != nil {
			log.Fatal(err)
		}

		expiryTime := strings.Split(string(valueStr), "\n\r")[0]
		expiryTimeInt, err := strconv.ParseInt(string(expiryTime), 10, 64)
		if err != nil {
			log.Fatal(err)
		}

		keysExpiry = append(keysExpiry, KeyExpiry{Key: string(key), ExpiryTime: expiryTimeInt})
	}

	// Sort the slice by expiry time
	sort.Slice(keysExpiry, func(i, j int) bool {
		return keysExpiry[i].ExpiryTime > keysExpiry[j].ExpiryTime
	})

	// Generate HTML
	for _, ke := range keysExpiry {
		valueStr, err := birdBase.Get([]byte(ke.Key))
		if err != nil {
			log.Fatal(err)
		}

		description := ""
		if len(strings.Split(string(valueStr), "\n\r")) == 2 {
			description = strings.Split(string(valueStr), "\n\r")[1]
		}

		duration := durafmt.Parse(time.Second * time.Duration(ke.ExpiryTime-time.Now().Unix()))

		if !isAdmin {
			html += fmt.Sprintf(`
			<div class="border rounded-lg overflow-hidden">
				<a href="https://%s/%s" target="_blank">
					<img class="w-full h-96 object-contain" src="https://%s/%s" alt="%s">
				</a>
				<div class="p-4">
					<h2 class="font-bold mb-2">%s</h2>
					<p class="text-gray-700">%s</p>
					<p class="text-sm text-gray-500">Expires: %s</p>
				</div>
			</div>
		`, config.Host, ke.Key, config.Host, ke.Key, ke.Key, ke.Key, description, duration)
		} else {
			html += fmt.Sprintf(`
			<div class="border rounded-lg overflow-hidden">
				<a href="https://%s/%s" target="_blank">
					<img class="w-full h-96 object-contain" src="https://%s/%s" alt="%s">
				</a>
				<div class="p-4">
					<h2 class="font-bold mb-2">%s</h2>
					<p class="text-gray-700">%s</p>
					<p class="text-sm text-gray-500">Expires: %s</p>
					<a href="https://%s/delete?delete=%s&key=%s" class="mt-2 bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded inline-block">
						Delete
					</a>
				</div>
			</div>
		`, config.Host, ke.Key, config.Host, ke.Key, ke.Key, ke.Key, description, duration, config.Host, ke.Key, config.AdminGalleryKey)
		}

	}

	html += `
            </div>
        </div>
    </body>
    </html>
    `

	return html
}