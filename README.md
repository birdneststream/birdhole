# Birdhole

Birdhole is the prestigious new file sharing service currently integrated with Aibird.

It isn't a public file sharing service and probably wont be open for anyone to upload.

* It requires an API key to upload to `/hole`
  * Each image will keep track of visits, timestamps and expiry times
  * Every visit to an item will increase the expiry time
  * Once an image has expired it is removed forever
* The gallery view also requires a key in the URL
  * Can sort by latest, popularity and expiry.
* Admin has their own key to delete images from the gallery view

## Setup

* Clone the repo
* Copy .config.toml.example to config.toml
  * Fill in your values

Run this from some reverse proxy stuff.