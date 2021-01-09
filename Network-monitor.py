import os, socket#, platform, subprocess, threading, requests
from datetime import datetime
from tkinter import *
from tkinter import filedialog #wasn't working with only * above
#from tkinter import ttk
from scapy.all import *
from tld import get_tld

savedir='.'

#region GUI global
app=Tk() #appears if used in cmd. Here need app.mainloop()
'''Note: Can attach components to main app but also frames and cavas
         If attaching to app directly, Must refer global app in function because it is modified
         Can NOT use .grid() and .pack() in the same "div" (app/frame)
'''
#Containers
#canvas = Canvas(app, height=700, width=300, bg="#263D42")
#canvas.pack() #attach canvas
optionsframe = Frame(app) #bg="white" #frames are like divs
optionsframe.grid(row=0, column=0) #optionsframe.place(relx=0.1, rely=0.1, relwidth=0.8, relheight=0.8)
# devicesframe = Frame(app, bg="white") #frames are like divs
# devicesframe.place(relx=0.1, rely=0.1, relwidth=0.8, relheight=0.8)

#Devices Content
deviceslabel = Label(app, text="Devices detected:")
deviceslabel.grid(row=2, column=0, sticky=W) #sticky=W means align to west  #deviceslabel.pack()
deviceslist = Listbox(app, height=8, width=100, border=0)
deviceslist.grid(row=3, column=0, columnspan=3, rowspan=6, pady=20, padx=20)
# Create scrollbar
scrollbar1 = Scrollbar(app)
scrollbar1.grid(row=3, column=3)
# Set scroll to listbox
deviceslist.configure(yscrollcommand=scrollbar1.set)
scrollbar1.configure(command=deviceslist.yview)

'''NOTE: KEEP 6 Rows between Listbox and next Label no matter the height of the Listbox'''
#Activity Content
activitylabel = Label(app, text="Activity detected:")
activitylabel.grid(row=9, column=0, sticky=W) #sticky=W means align to west  #deviceslabel.pack()
activitylist = Listbox(app, height=8, width=75, border=0)
activitylist.grid(row=10, column=0, columnspan=3, rowspan=6, pady=20, padx=20)
# Create scrollbar
scrollbar2 = Scrollbar(app)
scrollbar2.grid(row=10, column=3)
# Set scroll to listbox
activitylist.configure(yscrollcommand=scrollbar2.set)
scrollbar2.configure(command=deviceslist.yview)

#endregion

def SetGui():
    #Parts
    '''NOTE: Setting to Frame NOT App otherwise buttons columns stretch with the biggest Listbox'''
    scanbtn = Button(optionsframe, text="Scan", padx=20, pady=10, fg='black', bg="#E8E8E8", command=Scan)
    scanbtn.grid(row=0, column=0, pady=5) #.pack()
    selectbtn = Button(optionsframe, text="Select", padx=12, pady=10, fg='black', bg="#E8E8E8", command=Selectdev)
    selectbtn.grid(row=0, column=1, pady=5, padx=5) #.pack()
    monitorbtn = Button(optionsframe, text="Monitor", padx=12, pady=10, fg='black', bg="#E8E8E8", command=Monitor)
    monitorbtn.grid(row=0, column=2, pady=5, padx=5) #.pack()
    stopmonitorbtn = Button(optionsframe, text="Stop monitoring", padx=12, pady=10, fg='black', bg="#E8E8E8", command=StopMonitor)
    stopmonitorbtn.grid(row=0, column=3, pady=5, padx=5) #.pack()  
    selectdir = Button(optionsframe, text="Select save directory", padx=12, pady=10, fg='black', bg="#E8E8E8", command=SelectSavedir)
    selectdir.grid(row=0, column=4, pady=5, padx=5) #.pack() 

    #Main stuff
    app.title('Network Monitor')
    app.geometry('700x500') #If not included, the app will flex automatically when opened, to fit everything on screen

def geturl(packet): #Must be defined before class since used in global class var, otherwise error
    if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
        srcname,destname = packet[IP].src , packet[IP].dst
        devname=''
        # for dev in Device.selecteddevs:
        #     if(srcname == dev.ip):
        #         devname=dev.name
        #         break
        #     else:
        #         return
        #region PROBLEM: Slowing down (+freezing) program
        # try:
        #     srcname=socket.gethostbyaddr(srcname)[0]
        #     print(srcname,end=" ")
        # except:
        #     pass
        # try:
        #     destname=socket.gethostbyaddr(destname)[0]
        #     print(destname)
        # except:
        #     pass
        #endregion

        #region OUTPUT
        print(destname,"received packet from", srcname) #ALSO WORKS FOR NAMES OF DEVICES INSIDE NETWORK
        message=str(destname)+" received packet from "+str(srcname)
        activitylist.insert(END, message)
        # f.write(message)
        #endregion

        # try: #in case url is CDN #PROBLEM
        #     res= get_tld(destname[0], as_object=True)
        #     print("tld:",res)
        #     domain = res.domain
        #     temp= domain +'.'+str(res)
        #     target= socket.gethostbyname(temp)  #needs input without http:// and with only domain
        #     print(temp,target)
        # except Exception as e:
        #     print(e)
     

devices=[]
class Device:
    numdevices = 0 #global class var. All instances of this class have the same value and can change it. Can be accessed directly through Device.numdevices
    selecteddevs=[]
    t = AsyncSniffer(prn=geturl, store=False) #NOTE: ALL THE PACKET SNIFFERS WILL CATCH THE SAME PACKETS, SO NO NEED FOR DUPLICATE. USE 1 PACKET SNIFFER AND CATCH ACTIVITY OF SELECTED IPS
    def __init__(self, mac, ip):
        self.mac = mac
        self.ip = ip
        try:
            self.name = socket.gethostbyaddr(ip)[0]
        except:
            self.name=''
        self.selected=False #default
        Device.numdevices+=1

    
    def Selectdev(self):
        self.selected=True
        Device.selecteddevs.append(self)
        print("Selected",self.mac)
    def Unselectdev(self):
        self.selected=False
        Device.selecteddevs.remove(self)
        print("Deselected",self.mac)

    @classmethod
    def StartMonitor(cls):   
        cls.start_time=datetime.now() #cls. so it can be accessed by other functions like StopMonitor below 
        print(cls.start_time)
        message="Started at "+str(cls.start_time)
        activitylist.insert(END, message)
        # f.write(message)
        cls.t.start()
    @classmethod
    def StopMonitor(cls):
        cls.t.stop()
        endtime=datetime.now()
        duration= endtime-cls.start_time
        message="Stopped at "+str(endtime)+" duration = "+str(duration)
        activitylist.insert(END, message)
        print(duration)
    
    @classmethod #Not specific to one instance and cannot acces an instance since no "self" attribute.
    def Shownumdevices(cls): #NOT self. Can be called directly through Device.Shownumdevices()
        print(cls.numdevices)

#region GUI stuff
def Scan():
    print("Scanning network...")
    deviceslist.delete(0,END) #empty listbox (Content output in GUI)
    for device in devices: #if using classes
        del device
    Device.numdevices=0
    devices.clear()

    #GETTING DEVICES:
    ip="192.168.1.1/24"
    arp = ARP(pdst=ip)                      #create an ARP packet where pdst is dest IP 
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  #create ethernet frame with broadcast dest MAC address
    arp_broadcast_packet = ether/arp        #append arp packet inside ethernet frame
    answered_packets = srp(arp_broadcast_packet, timeout=3, verbose=0)[0]
    
    for sent_packet,received_packet in answered_packets:
        #devices.append({'ip': received_packet.psrc, 'mac': received_packet.hwsrc})
        device= Device(received_packet.hwsrc, received_packet.psrc)
        devices.append(device)

    #print ARP table that contains available devices on the network
    #print("Your Network:")
    # print("-----------------------------------\nIP Address\tMAC Address\n-----------------------------------")
    # for host in devices:
    #     print("{}\t{}".format(host['ip'], host['mac']))

    if(len(devices)==0):
        print("No devices found. Make sure you are connected to a network.")
    else:
        print("Done!")
        Showdevices()

def Showdevices():
    # Remove old info
    # for widget in optionsframe.winfo_children(): #Using frame
    #     widget.destroy()
    # deviceslist.delete(0,END) # Already done above
    #Show new info
    for device in devices:
        # label = Label(devicesframe, text=device)
        # label.pack()
        deviceslist.insert(END, (device.mac, device.ip, device.name))


def Selectdev():
    global selected_item
    index = deviceslist.curselection()[0]
    selected_item = deviceslist.get(index)
    print(selected_item, type(selected_item))
    device=''
    for dev in devices:
        if (selected_item[0]==dev.mac):
            device=dev
    if(device.selected==False):
        device.Selectdev()
    else:
        device.Unselectdev()

def SelectSavedir():
    global savedir
    # filename = filedialog.askopenfilename(initialdir="/", title="Select file", filetypes=(("executables", "*.exe"), ("all files", "*.*")))
    savedir = filedialog.askdirectory()
    print(str(savedir))

#endregion

#region GUI FUNCTIONS
def Monitor():
    # if(len(Device.selecteddevs)==0):
    #     print("No devices selected. Please select at least one.")
    #     return
    print("Monitoring...")
    Device.StartMonitor()
    # for device in devices:
    #     device.StartMonitor()

def StopMonitor():
    Device.StopMonitor()
    # for device in devices:
    #     device.StopMonitor()
    print('Stopped')
    Output()

def Output(): #DO THIS WHILE OUTPUTING ON GUI (in geturl()) NO NEED FOR SEPERATE FUNCTION
    for device in devices:
        print(device.mac)
        # completename = os.path.join(save_path, device.name+".txt")
        # f =  open(completeName, "w")
        # f.write()
        # f.close()

#endregion

if __name__ == "__main__":  
    SetGui()
    Scan() #autoscan at beginning
    app.mainloop() #GUI DOESN'T APPEAR BEFORE THIS COMMAND
    #DOESN'T run here since mainloop running: Scan() #autoscan at beginning
    # Output()