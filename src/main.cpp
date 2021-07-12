#include <Arduino.h>
#include <EEPROM.h>

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
    char          targets;
    const uint8_t *source;
    const char    *dev_type;
    int            msg_type = 0; // default is NOTIFY
    const char    *action;
    CBORPair       body;
    Message();
};

Message::Message(){
}


void loop(){

  // size_t free8start, free32start;

  char buf[1024];
  Message msg = Message();

  nonce_t nonce;
  unsigned long sec,usec;
  int b64_len;
  char *b64;
  uint8_t *clear; 
  uint16_t size;
  base64_decodestate b64_state;

   if (WiFi.status() != WL_CONNECTED) {
    Serial.print("# Error: no network\n");
    return;
  }

  
  int packetSize = mcast.parsePacket();
  if (packetSize) {
    // size_t x = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    // printf("Free_heap %d : %d\n",i, x );

    // free8start = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    // free32start = heap_caps_get_free_size(MALLOC_CAP_32BIT);
    // Serial.printf("Free 8bit-capable memory (start): %dK, 32-bit capable memory %dK\n", free8start, free32start);

    // read the packet into packetBufffer
    
    int len =  mcast.read((char *) &buf,1024);
    if (len > 0) {
      buf[len] = 0;}

    CBOR cbor_data = CBOR((uint8_t *)buf, len);

    msg.version=(int)cbor_data[0];
    msg.time = (long)cbor_data[1];
    msg.timestamp2 = (long)cbor_data[2];

    const uint8_t* ciph;
    ciph = cbor_data[4];

    Serial.println("MESSAGE");
    Serial.println((String)"Version : "+msg.version);
    Serial.println((String)"Time : "+msg.time);
    Serial.println((String)"Timestamp : "+msg.time+" , "+msg.timestamp2);

    // Init chacha cipher 
    chacha.clear();
    chacha.setKey(XAAL_KEY,32);

    // additionnal data
    chacha.addAuthData("[]",2);

    // Nonce 
    nonce.sec = __bswap_64(sec);
    nonce.usec = __bswap_32(usec);
    
    chacha.setIV(nonce.buf,12);
    clear  = (uint8_t *) malloc(sizeof(uint8_t) * size);
    chacha.decrypt(clear,ciph,size);

    CBOR payload = CBOR(clear, size);


  }
}


/*
// Init chacha cipher 
    chacha.clear();
    chacha.setKey(XAAL_KEY,32);

    // additionnal data
    chacha.addAuthData("[]",2);

    // Nonce 
    nonce.sec = __bswap_64(sec);
    nonce.usec = __bswap_32(usec);
    
    chacha.setIV(nonce.buf,12);
    clear  = (uint8_t *) malloc(sizeof(uint8_t) * size);
    chacha.decrypt(clear,(const uint8_t*)b64,size);

    Serial.println(clear[2]);

    // Serial.println("Contents:");
    // Serial.println(buf);

    DeserializationError error_json = deserializeJson(Data,buf);


    // Serial.print("targets : ");
    // Serial.println(targets);


    if (String(targets)=="ab"){

      JsonArray timestamp = Data["timestamp"];
      // Serial.print("timestamp : ");
      sec = timestamp[0];
      usec = timestamp[1];
      // Serial.print(sec);
      // Serial.print(" , ");
      // Serial.println(usec);
    
    //   // let's base64 decode the payload
      
      const char* payload = Data["payload"];
      size = strlen(payload) ;
      b64_len = ((size+1)*6)/8 ; // base64_decode_expected_len(size)+1; 
      b64 = (char *) malloc(b64_len);
      base64_init_decodestate(&b64_state);
      b64_len = base64_decode_block(payload, size, b64, &b64_state);
      
      size = b64_len - IETF_ABITES ; 

      // Init chacha cipher 
      chacha.clear();
      chacha.setKey(XAAL_KEY,32);

      // additionnal data
      chacha.addAuthData("[]",2);

      // Nonce 
      nonce.sec = __bswap_64(sec);
      nonce.usec = __bswap_32(usec);
    
      chacha.setIV(nonce.buf,12);
      clear  = (uint8_t *) malloc(sizeof(uint8_t) * size);
      chacha.decrypt(clear,(const uint8_t*)b64,size);

      // printf("%d\n",clear);
      deserializeJson(Data_Payload,clear);

      header = Data_Payload["header"];

      Serial.print("{header:  ");
      const char*  source = header["source"]; //header
      Serial.print("source : ");
      Serial.printf(source);

      const char*  msgType = header["msgType"]; //msgType
      Serial.print("  msgType : ");
      Serial.printf(msgType);

      const char*  devType = header["devType"]; //devType
      Serial.print("  devType : ");
      Serial.printf(devType);

      const char*  action = header["action"]; //action
      Serial.print("  action : ");
      Serial.printf(action);
      Serial.print(" } ");

      Serial.printf("\n");


      if ( header["action"] == "on" ) {
        digitalWrite(ledPin1, HIGH);   
    
      }
      else if ( header["action"] == "off" ) {
        digitalWrite(ledPin1,LOW);
      }


      free(clear);
      free(b64);

      header.clear();
      Data_Payload.clear();
      */

      // printf("Free_heap:%d\n", heap_caps_get_free_size(MALLOC_CAP_INTERNAL));



    //   // free8 = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    //   // free32 = heap_caps_get_free_size(MALLOC_CAP_32BIT);
    //   // printf("Free 8bit-capable memory (both reduced): %dK, 32-bit capable memory %dK\n", free8, free32);

    //}
    // printf("Free_heap:%d - %d\n", heap_caps_get_free_size(MALLOC_CAP_INTERNAL),i);
    // size_t y = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    // printf("Free_heap %d : %d\n",i, y );

    // printf("difference : %d\n",y-x);
    // i++;
    
    //Data.clear();

  //}}

