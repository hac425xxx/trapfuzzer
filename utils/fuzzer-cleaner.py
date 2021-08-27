import shutil
import os
import re
import time


def clean_dir_list(dir_list):
    for d in dir_list:
        for f in os.listdir(d):
            fpath = os.path.join(d, f)
            try:
                os.remove(fpath)
            except:
                pass


if __name__ == "__main__":

    dir_list = ["C:\\Users\\hac425\\AppData\\Local\\Temp"]

    while True:
        clean_dir_list(dir_list)
        time.sleep(10 * 60)
