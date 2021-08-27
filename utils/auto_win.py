# -*- coding: UTF-8 -*-
import sys
import autoit
import time
from datetime import datetime
class PopUpKiller:
    def __init__(self):
        None
    def POPUpKillerThread(self):
        print '[+] '+ datetime.now().strftime("%Y:%m:%d::%H:%M:%S") +' POP Up killer Thread started..'
        while True:
            time.sleep(0.1)
            try:
                # MS Word
                if "Word found unreadable" in autoit.win_get_text('Microsoft Word'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "You cannot close Microsoft Word because" in autoit.win_get_text('Microsoft Word'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "caused a serious error the last time it was opened" in autoit.win_get_text('Microsoft Word'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "Word failed to start correctly last time" in autoit.win_get_text('Microsoft Word'):
                    autoit.control_click("[Class:#32770]", "Button2")
                if "This file was created in a pre-release version" in autoit.win_get_text('Microsoft Word'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "The program used to create this object is" in autoit.win_get_text('Microsoft Word'):
                    autoit.control_click("[Class:#32770]", "Button1") 
                if "Word experienced an error trying to open the file" in autoit.win_get_text('Microsoft Word'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "experienced an error trying to open the file" in autoit.win_get_text('Microsoft Word'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "Word was unable to read this document" in autoit.win_get_text('Microsoft Word'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "The last time you" in autoit.win_get_text('Microsoft Word'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "Safe mode could help you" in autoit.win_get_text('Microsoft Word'):
                    autoit.control_click("[Class:#32770]", "Button2")
                if "You may continue opening it or perform" in autoit.win_get_text('Microsoft Word'):    
                    autoit.control_click("[Class:#32770]", "Button2")  # Button2 Recover Data or Button1 Open
                #Outlook
                if "Safe mode" in autoit.win_get_text('Microsoft Outlook'):    
                    autoit.control_click("[Class:#32770]", "Button2")  # Button2 Recover Data or Button1 Open
                if "Your mailbox has been" in autoit.win_get_text('Microsoft Exchange'):    
                    autoit.control_click("[Class:#32770]", "Button2")  # Button2 Recover Data or Button1 Open
                
                # MS Excel 
                if "Word found unreadable" in autoit.win_get_text('Microsoft Excel'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "You cannot close Microsoft Word because" in autoit.win_get_text('Microsoft Excel'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "caused a serious error the last time it was opened" in autoit.win_get_text('Microsoft Excel'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "Word failed to start correctly last time" in autoit.win_get_text('Microsoft Excel'):
                    autoit.control_click("[Class:#32770]", "Button2")
                if "This file was created in a pre-release version" in autoit.win_get_text('Microsoft Excel'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "The program used to create this object is" in autoit.win_get_text('Microsoft Excel'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "because the file format or file extension is not valid" in autoit.win_get_text('Microsoft Excel'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "The file you are trying to open" in autoit.win_get_text('Microsoft Excel'):    
                    autoit.control_click("[Class:#32770]", "Button1")
                if "The file may be corrupted" in autoit.win_get_text('Microsoft Excel'):
                    autoit.control_click("[Class:#32770]", "Button2")
                if "The last time you" in autoit.win_get_text('Microsoft Excel'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "We found" in autoit.win_get_text('Microsoft Excel'):
                    autoit.control_click("[Class:#32770]", "Button1")
                    
                #PPT

                # print autoit.win_get_text('Microsoft PowerPoint')

                ppt_text = autoit.win_get_text('Microsoft PowerPoint')

                if u"出现严重错误" in ppt_text:
                    # print "kkkk"
                    autoit.control_click("[Class:#32770]", "Button1")

                if u"无法编辑此" in ppt_text:
                    # print "kkkk"
                    autoit.control_click("[Class:#32770]", "Button1")
                if ppt_text != "":
                    print ppt_text

                if u"密码" in ppt_text:
                    # print "kkkk"
                    autoit.control_click("[Class:#32770]", "Button1")

                if u"示文稿中的一些控件无法激活" in ppt_text:
                    autoit.control_click("[Class:#32770]", "Button1")

                black_text = ["PowerPoint can't open", "Drawing conversion", "can't be ", " cannot ","repair "]

                for b in black_text:
                    if b in ppt_text:
                        autoit.control_click("[Class:#32770]", "Button1")
                    

                if "The last time you" in autoit.win_get_text('Microsoft PowerPoint'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "PowerPoint found a problem with content"  in autoit.win_get_text('Microsoft PowerPoint'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "read some content" in autoit.win_get_text('Microsoft PowerPoint'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "Sorry" in autoit.win_get_text('Microsoft PowerPoint'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "PowerPoint" in autoit.win_get_text('Microsoft PowerPoint'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "is not supported" in autoit.win_get_text('SmartArt Graphics'):
                    autoit.control_click("[Class:#32770]", "Button2")
                if "Safe mode" in autoit.win_get_text('Microsoft PowerPoint'):    
                    autoit.control_click("[Class:#32770]", "Button2")  # Button2 Recover Data or Button1 Open
            
                # Outlook
                
                # XPS Viewer
                if "Close" in autoit.win_get_text('XPS Viewer'):
                    autoit.control_click("[Class:#32770]", "Button1")
                if "XPS" in autoit.win_get_text('XPS Viewer'):
                    autoit.control_click("[Class:#32770]", "Button1")

                try:
                    autoit.win_close('[CLASS:bosa_sdm_msword]')
                except:
                    pass

                autoit.win_close('Password')




            except KeyboardInterrupt:
                return
            except Exception as e:
                # print e
                pass

if __name__ == "__main__":
    k = PopUpKiller()
    k.POPUpKillerThread()