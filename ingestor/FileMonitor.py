#!/usr/bin/env python

# modified script from:
#https://www.michaelcho.me/article/using-pythons-watchdog-to-monitor-changes-to-a-directory

#pip install observer
#pip install watchdog

import time, os, re
from datetime import datetime
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from VulntoES import NmapES

DIR_TO_WATCH = "/data/new/"
DIR_FOR_ERRORS = "/data/errors/"
DIR_FOR_PROCESSED = "/data/processed/"
DIR_FOR_WORK = "/data/queue/"
DIR_FOR_SAMPLES = "/data/samples/"
ALL_DIRS = [ DIR_FOR_ERRORS, DIR_FOR_PROCESSED, DIR_FOR_WORK, DIR_FOR_SAMPLES ]

class Watcher:
    def __init__(self):
        self.observer = Observer()
        if not os.path.exists(DIR_TO_WATCH):
            raise('Watch directory does not exist: %s' % DIR_TO_WATCH)

        if not os.path.exists(DIR_FOR_ERRORS):
            os.makedirs(DIR_FOR_ERRORS)
        
        if not os.path.exists(DIR_FOR_PROCESSED):
            os.makedirs(DIR_FOR_PROCESSED)

        if not os.path.exists(DIR_FOR_WORK):
            os.makedirs(DIR_FOR_WORK)
            
    def run(self):
        event_handler = Handler()
        self.observer.schedule(event_handler, DIR_TO_WATCH, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(5)
        except:
            self.observer.stop()
            print "Error"

        self.observer.join()


class Handler(FileSystemEventHandler):
    @staticmethod
    def on_any_event(event):
        # Don't process directories
        if event.is_directory:
            return None
            
        # Don't process files created in the working sub directories
        if any(work_dir in event.src_path for work_dir in ALL_DIRS):
            return None
            
        elif event.event_type == 'created':
            # Take action when a file is first created.
            print "Received created event - %s." % event.src_path
            process_file(event.src_path)

        #elif event.event_type == 'modified':
        #   # Take action when a file is modified.
        #   print "Received modified event - %s." % event.src_path

def process_file(path):
    new_path, filename = os.path.split(path)
    
    # Files without extensions are ignored
    if not '.' in path:
        return

    #create a timestamp
    timestamp = datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M%S')
    fname, ext = filename.split(".")
    processed_name = "%s_%s.%s" % (timestamp, fname, ext)
    processed_path = ""

    # verify xml file
    if filename.endswith('_nmap.xml'):
        # move it to DIR_FOR_WORK
        working_file = "%s%s" % (DIR_FOR_WORK, filename)
        print path
        print working_file
        os.rename(path, working_file)
        
        # create tags from the filename
        tags = ";".join(filename.split('.')[0].split('_'))
        
        # the app is the first tag
        app = tags.split(";")[0]

        # index is based on the app name, only alphanumeric - and lowercase
        pattern = re.compile('[\W_]+')
        index = "nmap_%s" % pattern.sub('',app.lower())
                                           
        print "Working on: %s" % working_file
        print "Index: %s" % index
        print "Tags: %s" % tags
        print "Sending Nmap data to Elasticsearch"

        try:
            np = NmapES(working_file, "elasticsearch", 9200, index, tags, app)
            np.toES()
            np.refreshNmapIndex()

            print "Done."
            print "Moving processed file to %s" % DIR_FOR_PROCESSED
            processed_path = "%s%s" % (DIR_FOR_PROCESSED, processed_name)
        except Exception, e:
            print "Error %s" %e
            print "Moving file to %s" % DIR_FOR_ERRORS
            processed_path = "%s%s" % (DIR_FOR_ERRORS, processed_name)

        os.rename(working_file, processed_path)
        print processed_path
        
    else:
        # move the file to the DIR_FOR_ERRORS
        processed_path = "%s%s" % (DIR_FOR_ERRORS, processed_name)
        os.rename(path, processed_path)
        print('New file found with a name that does not end with _nmap.xml')
        print('File was moved to: %s' % DIR_FOR_ERRORS)
        return
            
if __name__ == '__main__':
    w = Watcher()
    w.run()
