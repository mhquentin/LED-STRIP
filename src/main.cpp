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
    uint8_t       *targets;
    const uint8_t *source;
    const char    *dev_type;
    int            msg_type = 0; // default is NOTIFY
    const char    *action;
    CBORPair       body;
    Message();
    void dump();
};

Message::Message(){
}

void Message::dump() {
  Serial.printf("msg_type: %d action: %s\n",msg_type,action);
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

bool ALIVE_check(const uint8_t *buf) {
  for (size_t i=0 ; i < 15 ; i++) {
    if (buf[i] != 0){
      return 0;
    }
  }
  return 1;
}

bool UUID_check(const uint8_t *buf) {
  for (size_t i=0 ; i < 15 ; i++) {
    if (buf[i] != UUID[i]){
      return 0;
    }
  }
  return 1;
}

uint8_t *toByteString (CBOR buf) {
  //uint8_t *data; 
  size_t data_len = buf.length();
  //data = (uint8_t *) malloc(sizeof(uint8_t) * data_len);
	uint8_t data[data_len] = {};
  buf.get_bytestring(data);
  return data ;
}

void sendMessage(Message msg) {
  unsigned long sec,usec;
  nonce_t nonce;
  uint8_t *cypher; 
  uint16_t size;
  
  if (WiFi.status() != WL_CONNECTED) {
    Serial.print("# Error: no network\n");
    return;
  }
   CBORArray data = CBORArray();
  // ------------- headers -------------
  // version 
	data.append(7);
  // timestamp
  sec = timeClient.getEpochTime();
  usec = micros();
  data.append(sec);
  data.append(usec);

  // target is a list of address in bytes format.
  // in CBOR an empty list = 0x80, encoded in byte format, this shoud be [0x41,0x80]
  CBOR targets = CBOR();
  const uint8_t * ad = CBORArray(0).to_CBOR();
  targets.encode(ad, 1);
  data.append(targets);

  // ------------- payload -------------
  // source uuid address
  CBORArray buf = CBORArray();
  CBOR source = CBOR();
  source.encode(msg.source,16);
  buf.append(source);
  buf.append(msg.dev_type);
  buf.append(msg.msg_type);
  buf.append(msg.action);
  if (msg.body.length()!=0)
    buf.append(msg.body);

  // ------------- cyphering -------------
  chacha.clear();
  chacha.setKey(XAAL_KEY,32);
  // Nonce 
  nonce.sec =  __bswap_64(sec);
  nonce.usec = __bswap_32(usec);

  chacha.setIV(nonce.buf,12);
  // additionnal data
  chacha.addAuthData(CBORArray(0).to_CBOR(),1);
  // let's cipher & tag the buf
  size = buf.length();
  cypher = (uint8_t *) malloc(sizeof(uint8_t) * (size + IETF_ABITES));
  chacha.encrypt(cypher,(const uint8_t*)buf.to_CBOR(),size);
  // in combined mode ChachaPoly provide auth tag after ciphered data
  chacha.computeTag(cypher+size,IETF_ABITES);
  size = size + IETF_ABITES;

  // adding  cyphered payload
  CBOR tmp = CBOR();
  tmp.encode(cypher,size);
  data.append(tmp);
  
  // ------------- mcast sending ------------
  const uint8_t *cbor_encoded = data.to_CBOR();
  //hexdump(cbor_encoded,data.length());
  mcast.beginMulticastPacket();
  mcast.write(cbor_encoded,data.length());
  mcast.endPacket();
  Serial.print("Sent msg: " );
  msg.dump();
}

void sendAlive() {
  Message msg = Message();
  msg.source = UUID;
  msg.dev_type = "ledstrip.basic";
  msg.action = "alive";
  msg.body.append("timeout",600);
  sendMessage(msg);
}

void sendDescription() {
  Message msg = Message();
  msg.source = UUID;
  msg.dev_type = "ledstrip.basic";
  msg.msg_type = 2; // REPLY
  msg.action = "get_description";
  msg.body.append("vendor_id","Expressif");
  msg.body.append("product_id","ESP32 2AC7Z");
  msg.body.append("info",WiFi.localIP().toString().c_str());
  sendMessage(msg);
}

void sendStatus() {
  Message msg = Message();
  msg.source = UUID;
  msg.dev_type = "ledstrip.basic";
  msg.action = "attributes_change";
  msg.body.append("Led strip", digitalRead(ledPin1));
  sendMessage(msg);
  
}

void loop(){

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

    Serial.println("\n---------- NOUVEAU MESSAGE ----------");
    
    int len =  mcast.read((char *) &buf,1024);
    if (len > 0) {
      buf[len] = 0;}

    CBOR cbor_data = CBOR((uint8_t *)buf, len);

    msg.version = (int)cbor_data[0];
    msg.time = (long)cbor_data[1];
    msg.timestamp2 = (long)cbor_data[2];    

    sec = msg.time;
    usec = msg.timestamp2;

    Serial.println("----- MESSAGE -----");
    Serial.println((String)"Version : "+msg.version);
    Serial.println((String)"Time : "+msg.time);
    Serial.println((String)"Timestamp : "+msg.time+" , "+msg.timestamp2);
    Serial.print("Target : ");      

    size_t targets_len= (cbor_data[3]).length();
	  uint8_t data_targets[targets_len] = {};
    cbor_data[3].get_bytestring(data_targets);
    //uint8_t *data_targets = toByteString(cbor_data[3]);

    CBOR targets =CBOR((uint8_t *)data_targets,targets_len);
    uint8_t data[16]={};
    for (int i=0 ; i < targets.n_elements() ; i++) {
      targets[i].get_bytestring(data);
    }
    hexdump(data,16);

    size_t ciph_len= (cbor_data[4]).length();
	  uint8_t ciph[ciph_len] = {};
    cbor_data[4].get_bytestring(ciph);

    // Init chacha cipher 
    chacha.clear();
    chacha.setKey(XAAL_KEY,32);

    // additionnal data 
    // A CHANGER, PAS CA A FAIRE
    //RECUPERER AUTHDATA ET VERIFIER = TARGET
    //chacha.addAuthData("[]",2);

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
    
	  uint8_t data_source[16]={};
    payload[0].get_bytestring(data_source);

    msg.dev_type = (const char *)devmsg;
    msg.msg_type = (int)payload[2];
    msg.action = (const char *)actionmsg;
    //msg.source = (const uint8_t *)sourcemsg;

    Serial.println("\n----- PAYLOAD -----");
    Serial.println((String)"DevType : "+msg.dev_type);
    Serial.println((String)"MsgType : "+msg.msg_type);
    Serial.println((String)"Action : "+msg.action);


    // TRAITEMENT BODY
    /*if (payload.n_elements()>3){
      //msg.body = (CBORPair)payload[4];
      Serial.println("Dictionnaire : ok");
      CBORPair cbor_dict = (CBORPair)payload[4];
      
      //Explore the whole array
      for (size_t i=0 ; i < cbor_dict.n_elements() ; ++i) {
	    CBOR cbor_key = cbor_dict.key_at(i);
	    CBOR cbor_val = cbor_dict.at(i); //or cbor_val[cbor_dict.key_at(i)] (slower in this context)
      Serial.println(cbor_key.to_string());
      Serial.println(cbor_val.to_string());
     }
    }*/

    if (UUID_check(data)){
      if ((String)msg.action=="on"){
        digitalWrite(ledPin1, HIGH);
        sendStatus();
      }
      
      if ((String)msg.action=="off"){
        digitalWrite(ledPin1, LOW);
        sendStatus();
      }
    }

    if (ALIVE_check(data)){
      sendAlive();
      sendDescription();
    }

    free(clear);
  }
}

