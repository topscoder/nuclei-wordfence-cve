from threading import Thread
from lib.parsers.wordfence_cve_page import wordfence_cve_page

class DownloadWorker(Thread):
    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            (url, outputfile, overwrite, force) = self.queue.get()
            try:
                wordfence_cve_page(url, outputfile, overwrite, force)
            finally:
                self.queue.task_done()