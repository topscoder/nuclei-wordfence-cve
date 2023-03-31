from threading import Thread
from lib.parsers.WordfenceParser import WordfenceParser

class DownloadWorker(Thread):
    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            (url, outputfile, overwrite, force, overwrite_enhanced) = self.queue.get()
            try:
                parser = WordfenceParser()
                parser.run(url, outputfile, overwrite, force, overwrite_enhanced)
            except Exception as e:
                print(f'exception: {e}')
            finally:
                self.queue.task_done()