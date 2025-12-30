import cv2
import numpy as np

# Read the image
img = cv2.imread("iimg.jpg")

# Choose a key (integer)
key = 123

# Encrypt image using XOR
encrypted = cv2.bitwise_xor(img, key)
cv2.imwrite("encrypted.png", encrypted)

# Decrypt image (XOR again with same key)
decrypted = cv2.bitwise_xor(encrypted, key)
cv2.imwrite("decrypted.png", decrypted)
