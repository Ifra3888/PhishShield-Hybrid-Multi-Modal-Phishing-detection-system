import cv2


def scan_qr(image_path):
    img = cv2.imread(image_path)
    decoded = decode(img)
    
    for obj in decoded:
        return obj.data.decode("utf-8")
    
    return None