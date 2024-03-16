# Http endpoint to handle image optimizing

Stores optimized images in R2 to faster serve images.
Assumes the original image is stored in R2.
Assumes all images have unique IDs.
Sends a 1 year max age cache for any CDN that can be put in front of the the endpoint.

NODE ONLY
