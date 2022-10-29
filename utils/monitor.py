"""
    This module contains a Monitor class which handles watching files and directories.
    It is able to detect any changes in either files or directories and then report it.
"""
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler, LoggingEventHandler
import time
import os
import logging
import time
from pathlib import Path


# Initialize the logging configuration for logging directory and file changes.
logging.basicConfig(level=logging.INFO,
                format='%(asctime)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S',
                filename="../logs/monitor.log"
                # filename = "/home/spencer/school/comp8505/rootkit/logs/monitor.log" # Debug
                )


# Defining the default event handling code for files.
def on_created(event):
    logging.log(logging.INFO, f"File Created: {event.src_path}")

def on_deleted(event):
    logging.log(logging.INFO, f"File Deleted: {event.src_path}")

def on_modified(event):
    logging.log(logging.INFO, f"File Modified: {event.src_path}")

def on_moved(event):
    logging.log(logging.INFO, f"File Moved: {event.src_path} --> {event.dest_path}")


class FileSystemMonitor():

    __FILE = 1
    __DIRECTORY = 2
    __INVALID = 3

    def __init__(self, path=None):
        self.__path = None
        self.__threads = [] # List of threads watching directories.


    def shutdown(self):
        """
            Goes through all threads and shuts down each one.
        """
        for thread in self.__threads:
            thread.stop()
        for thread in self.__threads:
            thread.join()


    def __validate_path(self, path) -> int:
        """
            Checks if the given path is valid and returns a code
            which tells the programmer if the path points to a file, 
            directory, or is invalid.
        """
        if os.path.isdir(path):
            return self.__DIRECTORY
        elif os.path.isfile(path):
            return self.__FILE
        return self.__INVALID


    def __get_parent_directory(self, path) -> str:
        """
            Takes a path to a file as input, and returns the parent directory.
        """
        p = Path(path)
        return p.parent.absolute()


    def monitor(self, path: str):
        """
            Check if path is invalid, directory, or file.
        """
        code: int = self.__validate_path(path)
        if code == self.__INVALID:
            print(f"Path does not exist: {path}")
            exit(1)
        if code == self.__FILE:
            print(f"File: {path}")
            # Defining event handler which will only emit file specific events to the log file.
            event_handler = PatternMatchingEventHandler(patterns = [os.path.basename(path)],
                                                        ignore_directories=True,
                                                        ignore_patterns=None,
                                                        case_sensitive=True)
            event_handler.on_created = on_created
            event_handler.on_deleted = on_deleted
            event_handler.on_modified = on_modified
            event_handler.on_moved = on_moved
            parent_dir = self.__get_parent_directory(path)
            observer = Observer()
            observer.schedule(event_handler, parent_dir, recursive=False)
            observer.start()
            self.__threads.append(observer)
            return
        elif code == self.__DIRECTORY:
            print(f"Directory: {path}")
            event_handler = LoggingEventHandler()
            observer = Observer()
            observer.schedule(event_handler, path, recursive=False)
            observer.start()
            self.__threads.append(observer)
            return


# Example Usage
# if __name__ == "__main__":
#     FILESYSTEM_MONITOR = FileSystemMonitor()
#     FILESYSTEM_MONITOR.monitor("/home/spencer/school/comp8505/rootkit/utils/")
#     try:
#         time.sleep(60)
#     except KeyboardInterrupt:
#         FILESYSTEM_MONITOR.shutdown()
#         exit(1)
#     FILESYSTEM_MONITOR.shutdown()

