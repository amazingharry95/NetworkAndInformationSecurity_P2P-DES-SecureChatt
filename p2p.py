from Tkinter import *
from ttk import *
import socket
import thread
import des

class ChatClient(Frame):
  global chiper
  chiper = des.DES_Chiper("inikunci")
  
  def __init__(self, root):
    Frame.__init__(self, root)
    self.root = root
    self.initUI()
    self.serverSoc = None
    self.serverStatus = 0
    self.buffsize = 1024
    self.allClients = {}
    self.counter = 0
  
  def initUI(self):
    self.root.title("Peer to Peer")
    ScreenSizeX = self.root.winfo_screenwidth()
    ScreenSizeY = self.root.winfo_screenheight()
    self.FrameSizeX  = 550
    self.FrameSizeY  = 500
    FramePosX   = (ScreenSizeX - self.FrameSizeX)/2
    FramePosY   = (ScreenSizeY - self.FrameSizeY)/2
    self.root.geometry("%sx%s+%s+%s" % (self.FrameSizeX,self.FrameSizeY,FramePosX,FramePosY))
    self.root.resizable(width=False, height=False)
    
    padX = 10
    padY = 10
    parentFrame = Frame(self.root)
    parentFrame.grid(padx=padX, pady=padY, stick=E+W+N+S)
    
    ipGroup = Frame(parentFrame)
    serverLabel = Label(ipGroup, text="Set: ")
    self.nameVar = StringVar()
    self.nameVar.set("SDH")
    nameField = Entry(ipGroup, width=10, textvariable=self.nameVar)
    self.serverIPVar = StringVar()
    self.serverIPVar.set("127.0.0.1")
    serverIPField = Entry(ipGroup, width=15, textvariable=self.serverIPVar)
    self.serverPortVar = StringVar()
    self.serverPortVar.set("8090")
    serverPortField = Entry(ipGroup, width=5, textvariable=self.serverPortVar)
    serverSetButton = Button(ipGroup, text="Set", width=10, command=self.handleSetServer)
    addClientLabel = Label(ipGroup, text="Add friend: ")
    self.clientIPVar = StringVar()
    self.clientIPVar.set("127.0.0.1")
    clientIPField = Entry(ipGroup, width=15, textvariable=self.clientIPVar)
    self.clientPortVar = StringVar()
    self.clientPortVar.set("8091")
    clientPortField = Entry(ipGroup, width=5, textvariable=self.clientPortVar)
    clientSetButton = Button(ipGroup, text="Add", width=10, command=self.handleAddClient)
    serverLabel.grid(row=0, column=0)
    nameField.grid(row=0, column=1)
    serverIPField.grid(row=0, column=2)
    serverPortField.grid(row=0, column=3)
    serverSetButton.grid(row=0, column=4, padx=5)
    addClientLabel.grid(row=1, column=0)
    clientIPField.grid(row=1, column=2)
    clientPortField.grid(row=1, column=3)
    clientSetButton.grid(row=1, column=4, padx=5)

    writeChatGroup = Frame(parentFrame)
    writeLabel = Label(writeChatGroup, text="Tulis pesan: ")
    self.chatVar = StringVar()
    self.chatField = Entry(writeChatGroup, width=30, textvariable=self.chatVar)
    sendChatButton = Button(writeChatGroup, text="Kirim", width=10, command=self.handleSendChat)
    writeLabel.grid(row=0, column=0)
    self.chatField.grid(row=0, column=1, sticky=W)
    sendChatButton.grid(row=0, column=2, padx=5)
    
    readChatGroup = Frame(parentFrame)
    self.receivedChats = Text(readChatGroup, bg="grey", width=40, height=20, state=DISABLED)
    self.friends = Listbox(readChatGroup, bg="grey", width=30, height=20)
    self.receivedChats.grid(row=0, column=0, sticky=W+N+S, padx = (0,10))
    self.friends.grid(row=0, column=1, sticky=E+N+S)

  

    self.statusLabel = Label(parentFrame)

    bottomLabel = Label(parentFrame, text="")
    
    ipGroup.grid(row=0, column=0, pady=10)
    readChatGroup.grid(row=2, column=0)
    writeChatGroup.grid(row=1, column=0, pady=10)
    self.statusLabel.grid(row=3, column=0)
    bottomLabel.grid(row=4, column=0, pady=10)
    
  def handleSetServer(self):
    if self.serverSoc != None:
        self.serverSoc.close()
        self.serverSoc = None
        self.serverStatus = 0
    serveraddr = (self.serverIPVar.get().replace(' ',''), int(self.serverPortVar.get().replace(' ','')))
    try:
        self.serverSoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverSoc.bind(serveraddr)
        self.serverSoc.listen(5)
        self.setStatus("Server listening on %s:%s" % serveraddr)
        thread.start_new_thread(self.listenClients,())
        self.serverStatus = 1
        self.name = self.nameVar.get().replace(' ','')
        if self.name == '':
            self.name = "%s:%s" % serveraddr
    except:
        self.setStatus("Gagal melakukan setting ke server")
    
  def listenClients(self):
    while 1:
      clientsoc, clientaddr = self.serverSoc.accept()
      self.setStatus("Koneksi klien dari %s:%s" % clientaddr)
      self.addClient(clientsoc, clientaddr)
      thread.start_new_thread(self.handleClientMessages, (clientsoc, clientaddr))
    self.serverSoc.close()
  
  def handleAddClient(self):
    if self.serverStatus == 0:
      self.setStatus("Hubungkan alamat server terlebih dahulu")
      return
    clientaddr = (self.clientIPVar.get().replace(' ',''), int(self.clientPortVar.get().replace(' ','')))
    try:
        clientsoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientsoc.connect(clientaddr)
        self.setStatus("Terkoneksi ke klien pada %s:%s" % clientaddr)
        self.addClient(clientsoc, clientaddr)
        thread.start_new_thread(self.handleClientMessages, (clientsoc, clientaddr))
    except:
        self.setStatus("Gagal melakukan koneksi ke klien")

  def handleClientMessages(self, clientsoc, clientaddr):
    while 1:
      try:
        data = clientsoc.recv(self.buffsize)
        if not data:
            break
        self.addChat("%s:%s" % clientaddr, data)
      except:
          break
    self.removeClient(clientsoc, clientaddr)
    clientsoc.close()
    self.setStatus("Diskoneksi klien pada %s:%s" % clientaddr)
  
  def handleSendChat(self):
    if self.serverStatus == 0:
      self.setStatus("Hubungkan alamat server terlebih dahulu")
      return
    msg = self.chatVar.get()
    msg_encrypt = chiper.encrypt(msg)
    if msg == '':
        return
    self.addChat("me", msg_encrypt)
    for client in self.allClients.keys():
      client.send(msg_encrypt)
  
  def addChat(self, client, msg):
    self.receivedChats.config(state=NORMAL)
    data_decrypt = chiper.decrypt(msg)
    print "masuk atas"
    self.receivedChats.insert("end","\n"+client+": "+msg)
    self.receivedChats.insert("end","\n"+client+": "+data_decrypt+"\n")
    self.receivedChats.config(state=DISABLED)
  
  def addClient(self, clientsoc, clientaddr):
    self.allClients[clientsoc]=self.counter
    self.counter += 1
    self.friends.insert(self.counter,"%s:%s" % clientaddr)
  
  def removeClient(self, clientsoc, clientaddr):
      print self.allClients
      self.friends.delete(self.allClients[clientsoc])
      del self.allClients[clientsoc]
      print self.allClients
  
  def setStatus(self, msg):
    self.statusLabel.config(text=msg)
    print "message bawah"
    print msg
      
def main():  
  root = Tk()
  app = ChatClient(root)
  root.mainloop()  

if __name__ == '__main__':
  main()  
