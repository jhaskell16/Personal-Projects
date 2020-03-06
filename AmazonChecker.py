# James Haskell
# Python 3.7 -- Amazon listing Price Tracker
# 11/3/2019
# Guide used by 'Dev Ed' on YouTube

#/////////////////////////////////////////////////////////////////////////////////////////
#// Description: This program scrapes an Amazon listing of an EVGA GPU and tracks       //
#// the price once a day once the program starts. Once the price hits a desired price,  //
#// the program will e-mail the user about the drop in price                            //
#/////////////////////////////////////////////////////////////////////////////////////////

#Concepts Visited: Web Scraping, creating e-mail/server connections, Python libraries

#-----------------------------TO DO-------------------------------------------------------
# 1. Add GUI
# 2. Polish e-mail contents
# 3. Add feature to search for any amazon listing

import requests
from bs4 import BeautifulSoup
import smtplib
import time

#Change User-Agent to your specific one to work.
header = {"User-Agent" : ('USER AGENT GOES HERE')}
       
URL = input("Enter Amazon listing URL: ") 
 
def getTitle():
    page = requests.get(URL, headers=header)
    
    soup1 = BeautifulSoup(page.content, 'html.parser')
    soup2 = BeautifulSoup(soup1.prettify(), 'html.parser')
    
    title = soup2.find(id="productTitle").get_text()

    return title.strip()

print("\nCurrently Tracking: \'" + getTitle() + "\'")


def getPrice():
    page = requests.get(URL, headers=header)
    
    soup1 = BeautifulSoup(page.content, 'html.parser')
    soup2 = BeautifulSoup(soup1.prettify(), 'html.parser')

    price = soup2.find(id="priceblock_ourprice").get_text()

    if(len(price) <= 7):                                 #format $###.00 (up to hundreds)
        num_price = price[1:len(price) - 3]              #len() - 3 to omit float value (.99, etc.)
    elif(len(price) == 9):                               #thousands
        part1 = price[1:2]
        part2 = price[3:len(price) - 3]
        num_price = part1 + part2
    elif(len(price) == 10):                               #ten thousands
        part1 = price[1:3]
        part2 = price[4:len(price) - 3]
        num_price = part1 + part2
    elif(len(price) == 11):                              #hundred thousands
        part1 = price[1:4]
        part2 = price[5:len(price) - 3]
        num_price = part1 + part2
    
    return num_price

print("Current Price: $" + getPrice())     

desiredPrice = int(input("Enter your desired price for the item (integer): $"))


def evalPrice(desiredPrice):
    print("\nScraping Amazon website and listing...")
    
    if(float(getPrice()) <= desiredPrice):
        sendEmail(desiredPrice)
    else:
        print("\nItem has not dropped to desired price.\nCurrent price is: $" + getPrice())
        
def sendEmail(desiredPrice):
    print("Sending e-mail...")
    server = smtplib.SMTP('smtp.gmail.com', 587)                    #Gmail server
    server.ehlo()                                                   #EHLO => link between e-mail/server connections
    server.starttls()                                               #encrypt my connection
    server.ehlo()
    
    #Input your Gmail info
    server.login('email', 'password')
    
    #TO DO: Automate email contents based on chosen amazon item
    subject = "EVGA 1070 GPU Below $" + str(desiredPrice) + "!!"
    body = (getTitle() + " has dropped to under $" + getPrice() + "!\n\nGo to the following url to check the amazon listing:\nhttps://www.amazon.com/EVGA-GeForce-GAMING-Support-08G-P4-5173-KR/dp/B01KVZBNY0/ref=sr_1_1?keywords=1070+gpu&qid=1572832168&refinements=p_36%3A-49900&rnid=386442011&sr=8-1")
    
    message = f"Subject: {subject}\n\n{body}"
    
    server.sendmail(
            'from email',          #from
            'to email',     #to
            message)
    print("E-mail has been sent!")
    
    server.quit()

def checkPriceDrop(desiredPrice):                                           #indicates whether price has dropped to stop while loop
    if(int(getPrice()) <= desiredPrice):
        return True
    else:
        return False


interval = int(input("How often would you like to track the listing? (in seconds; 3600s = 1 hour, 86400s = 24 hours): "))
if(desiredPrice >= int(getPrice())):
    print("\nItem is at or below your desired price! An e-mail is being sent for cocnfirmation.")
    sendEmail(desiredPrice)
else:
    while(checkPriceDrop(desiredPrice) == False):
        evalPrice(desiredPrice)
        time.sleep(interval)                                               #Time interval to pause code in seconds (currently 24 hours)