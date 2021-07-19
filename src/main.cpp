#include <Arduino.h>
#include <EEPROM.h>
#include <string>
#include <config.h>
#include <YACL.h>
#include <WiFi.h>
#include <WiFiUdp.h>
WiFiUDP mcast;
WiFiUDP ntpUDP;

#include <NTPClient.h>
NTPClient timeClient(ntpUDP, "europe.pool.ntp.org", 0, 300 * 1000);

#include <ArduinoJson.h>

StaticJsonDocument<1024> Data;
StaticJsonDocument<1024> Data_Payload;
StaticJsonDocument<256> header;

#include <Crypto.h>
#include <ChaChaPoly.h>
ChaChaPoly chacha;

#include <byteswap.h>
#include <libb64/cdecode.h>


#define IETF_ABITES 16 
typedef union {
  unsigned char buf[12];
  struct {
    uint64_t sec;
    uint32_t usec; };
} nonce_t;

 int ledPin1 = 23;
int i = 0;

void wifiInit() {
  Serial.print("# Init WiFi\n");
  WiFi.begin(SSID, PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
  }
  Serial.print("# WiFi connected\n");
  Serial.print("# IP address: ");
  Serial.println(WiFi.localIP());
  mcast.beginMulticast(IPAddress(224,0,29,200),PORT);
}

void ntpInit() {
  timeClient.update();
  Serial.println("# Time : " + timeClient.getFormattedTime());
}

void LEDInit() {

  pinMode(ledPin1, OUTPUT);
  digitalWrite(ledPin1, LOW);
}

void setup()
{

  Serial.begin(115200);   // Starts serial communication in 9600 baud rate.
  wifiInit();
  ntpInit();
  LEDInit();
  
}

class Message {
  public:
    int           version;
    long          time;
    long          timestamp2;
    uint8_t targets[16]={};
    const uint8_t *source;
    const char    *dev_type;
    int            msg_type = 0; // default is NOTIFY
    const char    *action;
    CBORPair       body;
    Message();
};

Message::Message(){
}

void hexdump(const uint8_t *buf,int size) {
  Serial.print("[");
  for (size_t i=0 ; i < size ; ++i) {
    Serial.print("0x");
      Serial.print(buf[i], HEX);
    Serial.print(",");
    }
  Serial.print("]");
}



void loop(){

  // size_t free8start, free32start;

  char buf[1024];
  Message msg = Message();

  nonce_t nonce;
  unsigned long long sec;
  unsigned long usec;
  uint8_t *clear; 
  uint16_t size;

   if (WiFi.status() != WL_CONNECTED) {
    Serial.print("# Error: no network\n");
    return;
  }

  
  int packetSize = mcast.parsePacket();
  if (packetSize) {
    
    int len =  mcast.read((char *) &buf,1024);
    if (len > 0) {
      buf[len] = 0;}

    CBOR cbor_data = CBOR((uint8_t *)buf, len);

    msg.version = (int)cbor_data[0];
    msg.time = (long)cbor_data[1];
    msg.timestamp2 = (long)cbor_data[2];    

    sec = msg.time;
    usec = msg.timestamp2;

    size_t targets_len= (cbor_data[3]).length();
	  uint8_t data_targets[targets_len] = {};
    cbor_data[3].get_bytestring(data_targets);

    size_t ciph_len= (cbor_data[4]).length();
	  uint8_t ciph[ciph_len] = {};
    cbor_data[4].get_bytestring(ciph);

    Serial.println("MESSAGE");
    Serial.println((String)"Version : "+msg.version);
    Serial.println((String)"Time : "+msg.time);
    Serial.println((String)"Timestamp : "+msg.time+" , "+msg.timestamp2);
    hexdump(data_targets,targets_len);

    // Init chacha cipher 
    chacha.clear();
    chacha.setKey(XAAL_KEY,32);

    // additionnal data
    chacha.addAuthData("[]",2);

    // Nonce 
    nonce.sec = __bswap_64(sec);
    nonce.usec = __bswap_32(usec);
    
    chacha.setIV(nonce.buf,12);

    size = len - IETF_ABITES;

    clear  = (uint8_t *) malloc(sizeof(uint8_t) * size);
    chacha.decrypt(clear,(const uint8_t *)ciph,size);

    CBOR payload = CBOR(clear, size);

    size_t pld3= (payload[3]).length();
    uint8_t actionmsg[pld3] = {};
    payload[3].get_bytestring(actionmsg);

    size_t pld1= (payload[1]).length();
    uint8_t devmsg[pld1] = {};
    payload[1].get_bytestring(devmsg);
    
    size_t source_len= (payload[0]).length();
	  uint8_t data_source[source_len] = {};;
    payload[0].get_bytestring(data_source);

    


    msg.dev_type = (const char *)devmsg;
    msg.msg_type = (int)payload[2];
    msg.action = (const char *)actionmsg;
    //msg.source = (const uint8_t *)sourcemsg;

    CBORPair cbor_dict = CBORPair();
    
    //Serial.println(payload[4].length()>0);
    //Serial.println(payload[4].length());
    //payload[4].get_string
    if (payload[4].length()>0){
     /* msg.body = (CBORPair)payload[4];
      Serial.println("ok");
      //cbor_dict = (CBORPair)payload[4];
      
      char key[(msg.body).length()] = {};
      char value[(msg.body).length()] = {};
      for (size_t i=0 ; i < msg.body.n_elements() ; ++i) {
        CBOR cbor_key = msg.body.key_at(i);
        CBOR cbor_val = msg.body.at(i); //or cbor_val[cbor_dict.key_at(i)] (slower in this context)
        cbor_key.get_string(key);
        cbor_val.get_string(value);  
      Serial.println(key);
      Serial.println(value);
     }*/
    }

    payload[3].get_bytestring(actionmsg);
    
    Serial.println("PAYLOAD");
    Serial.println((String)"DevType : "+msg.dev_type);
    Serial.println((String)"MsgType : "+msg.msg_type);
    Serial.println((String)"Action : "+msg.action);
    hexdump(data_source,source_len);

    for (int i=2 ; i < 18 ; ++i) {
      msg.targets[i-2]=data_targets[i];
      hexdump(msg.targets,sizeof(msg.targets));
    }
    hexdump(msg.targets,targets_len);

    if (msg.targets == UUID){
      Serial.println("TARGET VALIDE");
    }

    Serial.println("\n");
    free(clear);
  }
}