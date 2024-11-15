eval('print("This is a test")')  # This should trigger a warning
os.system('dir')  # This should trigger a warning
socket.connect(('example.com', 80))  # This should trigger a warning