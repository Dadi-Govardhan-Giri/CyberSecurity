from PIL import Image
import piexif
import io

def add_fake_thumbnail(iimg, qmarkimg, output_path):
# add_fake_thumbnail("real.jpg", "fake.jpg", "output.jpg"):

    """
    iimg      -> path to the main image (shown when opened fully)
    qmarkimg  -> path to the fake image (shown in preview/thumbnail)
    output_path -> path where the new tricked image will be saved
    """

    # Load main image (the one that opens normally)
    main_img = Image.open(iimg)

    # Load thumbnail image and resize to EXIF thumbnail size
    thumb_img = Image.open(qmarkimg)
    thumb_img.thumbnail((128, 128))  # typical EXIF thumbnail size
    thumb_bytes = io.BytesIO()
    thumb_img.save(thumb_bytes, format="JPEG")
    
    # Create empty EXIF if missing
    try:
        exif_dict = piexif.load(main_img.info["exif"])
    except KeyError:
        exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None}
    
    # Insert fake thumbnail
    exif_dict["thumbnail"] = thumb_bytes.getvalue()
    
    # Export new image with fake preview
    exif_bytes = piexif.dump(exif_dict)
    main_img.save(output_path, "JPEG", exif=exif_bytes)

    print(f"✅ Output saved as {output_path}")
    print("👉 Preview will show qmarkimg, but opening shows iimg.")

# Example usage:add_fake_thumbnail("real.jpg", "fake.jpg", "final_tricked.jpg")
