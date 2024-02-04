package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gabriel-vasile/mimetype"
	"github.com/hako/durafmt"
)

type KeyExpiry struct {
	Key        string
	ExpiryTime int64
}

func galleryDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	if cleanString(r.URL.Query().Get("key")) != config.AdminGalleryKey {
		http.NotFound(w, r)
		return
	}

	// get the key from the url
	galleryItem := cleanString(r.URL.Query().Get("delete"))

	// delete the key from bird.db
	deleteFile(galleryItem)

	// redirect to gallery with key
	http.Redirect(w, r, "/gallery?key="+config.AdminGalleryKey, http.StatusSeeOther)
}

func galleryRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	urlKey := cleanString(r.URL.Query().Get("key"))

	// if the param has key = config.Key
	if urlKey != config.GalleryKey && urlKey != config.AdminGalleryKey {
		http.NotFound(w, r)
		return
	}

	isAdmin := urlKey == config.AdminGalleryKey
	sortBy := cleanString(r.URL.Query().Get("sortBy"))

	if sortBy == "" {
		sortBy = "new"
	}

	// return html with all images
	fmt.Fprint(w, galleryHtml(isAdmin, sortBy))
}

func galleryFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	// Return 404 if we do not match this regex
	validPath := regexp.MustCompile(`^/[a-zA-Z0-9]+\.[a-zA-Z]{3,4}$`)
	if !validPath.MatchString(r.URL.Path) {
		http.NotFound(w, r)
		return
	}

	http.ServeFile(w, r, config.FilePath+r.URL.Path[1:])

	// if the referer is not from the same host
	if !strings.Contains(r.Referer(), config.Host) {
		// If a file is previewed extend the time by 1 Hour
		if birdBase.Has([]byte(r.URL.Path[1:])) {
			valueStr, err := birdBase.Get([]byte(r.URL.Path[1:]))
			if err != nil {
				log.Fatal(err)
			}

			var fileInfo FileInfo
			err = json.Unmarshal(valueStr, &fileInfo)
			if err != nil {
				log.Fatal(err)
			}

			// if views is not out of bounds for int
			if fileInfo.Views < 2147483647 {
				fileInfo.Views = fileInfo.Views + 1
			}

			// If the fileInfo.KeyExpiry is not out of bounds for int64
			if fileInfo.KeyExpiry < 9223372036854775807-int64(3600*fileInfo.Views) {
				fileInfo.KeyExpiry = fileInfo.KeyExpiry + int64(3600*fileInfo.Views)
			}

			fileInfoJson, err := json.Marshal(fileInfo)
			if err != nil {
				log.Fatal(err)
			}

			err = birdBase.Put([]byte(r.URL.Path[1:]), fileInfoJson)
			if err != nil {
				log.Fatal(err)
			}
		}
	}

}

func galleryUpload(w http.ResponseWriter, r *http.Request) {
	// check if header value contains X-Auth-Token and it is set
	if cleanString(r.Header.Get("X-Auth-Token")) != config.Key {
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
		urlLen := cleanString(r.FormValue("url_len"))
		// convert urlLen to int
		urlLenInt, _ = strconv.Atoi(urlLen)
	}

	expiryInt := config.Expiry
	if r.FormValue("expiry") != "" {
		expiry := cleanString(r.FormValue("expiry"))
		// convert expiry to int64
		expiryInt, _ = strconv.ParseInt(expiry, 10, 64)
	}

	// description, if the length is over 2048 trim it
	description := r.FormValue("description")
	if len(description) > 2048 {
		description = description[:2048]
	}

	if description != "" {
		description = cleanString(description)
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
		Timestamp:   time.Now().Unix(),
		Description: description,
		Width:       0,
		Height:      0,
		Views:       0,
	}

	putFile(fileInfo, file, w)

	// return url with config.Host
	fmt.Fprintf(w, "%s/%s", "https://"+config.Host, fileName)
}

func galleryHtml(isAdmin bool, sortBy string) string {
	galleryKey := config.GalleryKey
	if isAdmin {
		galleryKey = config.AdminGalleryKey
	}

	// html start string
	html := fmt.Sprintf(`
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
            <div class="flex flex-wrap justify-center space-x-2 sm:space-x-4 mb-8">
                <a href="/gallery?key=%s&sortBy=new" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-1 sm:py-2 px-2 sm:px-4 rounded mb-2 sm:mb-0">New</a>
                <a href="/gallery?key=%s&sortBy=old" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-1 sm:py-2 px-2 sm:px-4 rounded mb-2 sm:mb-0">Old</a>
                <a href="/gallery?key=%s&sortBy=expiring_soon" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-1 sm:py-2 px-2 sm:px-4 rounded mb-2 sm:mb-0">Expiring Soon</a>
                <a href="/gallery?key=%s&sortBy=expiring_latest" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-1 sm:py-2 px-2 sm:px-4 rounded mb-2 sm:mb-0">Expiring Latest</a>
                <a href="/gallery?key=%s&sortBy=popular" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-1 sm:py-2 px-2 sm:px-4 rounded mb-2 sm:mb-0">Popular</a>
                <a href="/gallery?key=%s&sortBy=least_popular" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-1 sm:py-2 px-2 sm:px-4 rounded mb-2 sm:mb-0">Least Popular</a>
            </div>
            <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
    `, galleryKey, galleryKey, galleryKey, galleryKey, galleryKey, galleryKey)

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
		switch sortBy {
		case "new":
			return filesInfo[i].Timestamp > filesInfo[j].Timestamp

		case "old":
			return filesInfo[i].Timestamp < filesInfo[j].Timestamp

		case "expiring_soon":
			return filesInfo[i].KeyExpiry < filesInfo[j].KeyExpiry

		case "expiring_latest":
			return filesInfo[i].KeyExpiry > filesInfo[j].KeyExpiry

		case "popular":
			return filesInfo[i].Views > filesInfo[j].Views

		case "least_popular":
			return filesInfo[i].Views < filesInfo[j].Views

		default:
			return filesInfo[i].Timestamp > filesInfo[j].Timestamp
		}
	})

	// Generate HTML
	for _, fileInfo := range filesInfo {
		duration := durafmt.Parse(time.Second * time.Duration(fileInfo.KeyExpiry-time.Now().Unix()))

		html += fmt.Sprintf(`
			<div class="border rounded-lg overflow-hidden">
				<a href="https://%s/%s" target="_blank">
					<img class="w-full h-96 object-contain" src="https://%s/%s" alt="%s" loading="lazy">
				</a>
				<div class="p-4">
					<h2 class="font-bold mb-2">%s</h2>
					<p class="text-gray-700">%s</p>
					<p class="text-sm text-gray-500">Expires: %s</p>
					<p class="text-sm text-gray-500">Size: %.2f KB</p>
					<p class="text-sm text-gray-500">Views: %d</p>
		`, config.Host, fileInfo.Name, config.Host, fileInfo.Name, fileInfo.Name, fileInfo.Name, fileInfo.Description, duration, float64(fileInfo.Size)/1024.0, fileInfo.Views)

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
