from threading import Thread
from lib.parsers.WordfenceParser import WordfenceParser

class DownloadWorker(Thread):
    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            (url, outputfile, overwrite, force) = self.queue.get()
            try:
                parser = WordfenceParser()
                parser.run(url, outputfile, overwrite, force)
            finally:
                self.queue.task_done()