import sys
import hashlib
import datetime
import socket
from time import strftime, gmtime
import enum
from itertools import repeat

HOST= '103.99.168.100' # arbitrary choice from makeseed
PORT=8333
MAX_BLOCK_NUMBER = 10000
BLOCK_GENESIS = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
Block_19837 = 0x0000000054157cc9a1cf99b3a7f15f287dbe400d7c07c1bab51b193c3bceab90
BLOCK_9837 = 0x00000000acc0f1ca3334891819df9916b3e93aa7901bd2046fd9141fe065a05b
Block_122010 = 0x00000000000080006bce68e21d47dc51e115c2f32fc2de36e20334c377d61b28

VERSION = 70015
MAGIC = 0xf9beb4d9
TYPE_IDS = {1: 'MSG_TX', 2: 'MSG_BLOCK', 3: 'MSG_FILTERED_BLOCK', 4: 'MSG_CMPCT_BLOCK',
            11: 'MSG_WITNESS', 21: 'MSG_WITNESS_BLOCK', 31: 'MSG_FILTERED_WITNESS_BLOCK'}
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


class Lab5(object):
    def __init__(self, block_id):
        self.__block_id = block_id 
        self.node_address = (HOST, PORT)
        log_client("node:" , self.node_address)
        self.__api = BlockChainAPI.instance(self.node_address)  
        log_connection('connecting...')
        s.connect(self.node_address)
        log_connection('connected to ',  self.node_address)
        
    @property
    def block_id(self):
        return self.__block_id

    
    def start(self):
        log_client("starting....")
        log_client("block_id: ", self.__block_id)
        self.__api.authenticate()
        self.__api.ack()
        self.__api.get_blocks(BLOCK_GENESIS)
        self.__api.get_block_by_block_id(BLOCK_GENESIS, self.__block_id)
        self.__api.get_block(BLOCK_9837)
        self.__api.manipulate(Block_122010, "122010")

        
                   
#facad design pattern
class BlockChainAPI(object):
    _instance = None

    #singleton design pattern
    def __init__(cls):
        raise RuntimeError('Call instance() instead')

    @classmethod
    def instance(cls,node_address):
        if cls._instance is None:
            cls._instance = cls.__new__(cls)
            cls.node_address = node_address
        return cls._instance
    
    
    
    def authenticate(cls):
        date = datetime.datetime.now()
        
        header_map = {Keys.START_STRING: Char_4t_Value(MAGIC),
                       Keys.COMMAND: String_Value(Command.VERSION.value),
                       Keys.PAYLOAD: Uint32_t_Value(86)}
        
        content_map = {Keys.VERSION: Int32_t_Value(VERSION),
                       Keys.SERVICE: Uint64_t_Value(0x00),
                       Keys.TIMESTAMP: Int64_t_Value(date.strftime('%s'),date.strftime("%a, %d %b %Y %H:%M:%S GMT")),
                       Keys.RECV_SERVICE: Uint64_t_Value(0x01),
                       Keys.RECV_IP: Ipv6_from_ipv4_Value(HOST), 
                       Keys.RECV_PORT: Uint16_t_Value(PORT), 
                       Keys.TRANS_SERVICE: Uint64_t_Value(0x00),
                       Keys.TRANS_IP: Ipv6_from_ipv4_Value(socket.gethostbyname(socket.gethostname())),
                       Keys.TRANS_PORT: Uint16_t_Value(59550),
                       Keys.NONCE: Uint64_t_Value(0), 
                       Keys.USER_BYTES: Uint8_t_Value(0x00),
                       Keys.USER_AGENT: Empty_Value(''),
                       Keys.HEIGHT: Int32_t_Value(0), 
                       Keys.RELAY: Uint8_t_Value(0)}
       
        request = Request(Command.VERSION.value, header_map, content_map)
        request_bytes = request.to_bytes()
        print(request)
        
        output_messages = cls.call(request_bytes, Command.VERSION.value)
        cls.print_messages(output_messages)

    def ack(cls):
        header_map = {Keys.START_STRING: Char_4t_Value(MAGIC),
                       Keys.COMMAND: String_Value(Command.VERACK.value),
                       Keys.PAYLOAD: Uint32_t_Value(0)}
        
        request = Request(Command.VERACK.value, header_map,{})
        request_bytes = request.to_bytes()
        print(request)
        
        output_messages = cls.call(request_bytes, Command.VERACK.value)
        cls.print_messages(output_messages)
        

    def get_block_by_block_id(cls,block, block_id):
        original_count = int((block_id - 0) / 500)
        count = original_count
        
        while count > 0:
            
            header_map = {Keys.START_STRING: Char_4t_Value(MAGIC),
                       Keys.COMMAND: String_Value(Command.GETBLOCKS.value),
                       Keys.PAYLOAD: Uint32_t_Value(69)}
            
            
            content_map = {Keys.VERSION: Int32_t_Value(VERSION),
                      Keys.HASH_COUNT: Compactsize_t_Value(1),
                      Keys.HASH: Char_32t_Value(block),
                      Keys.STOP_HASH: Zero_fill_Value(0,31)}

            
            request = Request(Command.GETBLOCKS.value, header_map, content_map)
            request_bytes = request.to_bytes()
            print(request)
            
            output_messages = cls.call(request_bytes, Command.INV.value)
        
            response_message = output_messages.get_requested_message()
            
            for response_msg in response_message:
                if response_msg is not None:
                    print(response_msg)
                    block_byte = response_msg.get_block(500-1)
                
                    
                    if block_byte != None:
                        block = int(block_byte.to_hexa() , 16)
                        count -=1
                  
        my_block_count = (block_id - 0) - (original_count * 500)
        
        
        header_map = {Keys.START_STRING: Char_4t_Value(MAGIC),
                       Keys.COMMAND: String_Value(Command.GETBLOCKS.value),
                       Keys.PAYLOAD: Uint32_t_Value(69)}
            
            
        content_map = {Keys.VERSION: Int32_t_Value(VERSION),
                      Keys.HASH_COUNT: Compactsize_t_Value(1),
                      Keys.HASH: Char_32t_Value(block),
                      Keys.STOP_HASH: Zero_fill_Value(0,31)}

            
        request = Request(Command.GETBLOCKS.value, header_map, content_map)
        request_bytes = request.to_bytes()
        print(request)
        
        output_messages = cls.call(request_bytes, Command.INV.value)
    
        response_message = output_messages.get_requested_message()
        
        for response_msg in response_message:
            if response_msg is not None:
                print(response_msg)    
                block = response_msg.get_block(my_block_count-1)
                log_client("My block '{}' hash is: {}".format(block_id, block.to_hexa()))
            
        
    def get_blocks(cls, block):
        header_map = {Keys.START_STRING: Char_4t_Value(MAGIC),
                       Keys.COMMAND: String_Value(Command.GETBLOCKS.value),
                       Keys.PAYLOAD: Uint32_t_Value(69)}
                
        content_map = {Keys.VERSION: Int32_t_Value(VERSION),
                       Keys.HASH_COUNT: Compactsize_t_Value(1),
                       Keys.HASH: Char_32t_Value(block),
                       Keys.STOP_HASH: Zero_fill_Value(0,31)}

        request = Request(Command.GETBLOCKS.value, header_map, content_map)
        request_bytes = request.to_bytes()
        print(request)

        output_messages = cls.call(request_bytes, Command.INV.value)
        cls.print_messages(output_messages)
        
        
    def get_block(cls,block_id):
        header_map = {Keys.START_STRING: Char_4t_Value(MAGIC),
                       Keys.COMMAND: String_Value(Command.GETBLOCK.value),
                       Keys.PAYLOAD: Uint32_t_Value(34)}
                       
        content_map = {Keys.BLOCK_HASH: Char_32t_Value(block_id),
                       Keys.INDEXES_LENGTH: Compactsize_t_Value(1),
                       Keys.INDEXES: Compactsize_t_a_Value([1])}

        request = Request(Command.GETBLOCK.value, header_map, content_map)
        request_bytes = request.to_bytes()
        print(request)
        
        output_messages = cls.call(request_bytes, Command.BLOCK.value)
        cls.print_messages(output_messages)

    def manipulate(cls,block, block_id):
        print(cls.manipluation_report(block, block_id))
      
        
    def manipluation_report(cls, block, block_id):
        number_of_transactions = 5
        prev_block_hash = 0x00000000000049784cd4a88e8c08af66a8acc931067630dd21703311761e6ad2
        trans1 = 0xcb6e806df4eb7ddbedda877a6b32dc8a5870084fbef053c94244a8c0381bd651
        trans2 = 0x7584e8ce1746ec485b843aba1ba22eb97dafd7271641570a4723fc1da70fd01a
        trans3 = 0xf90dba09438faeb7a0755fe2c5edf0797ddeb6bd4715340b1d0ede801c3d1f8b
        trans4 = 0xcc3d23173356dcca2f8fe0f437595490ca3b0b4ef4580b12094ca604b57cdd25
        trans5 = 0xd316819521c252c0e55d00663e4e5ec103423b433de05f7c7d1424aa3f3288c1
        
        manipulatedTrans5 = 0xd416819521c252c0e55d00663e4e5ec103423b433de05f7c7d1424aa3f3288c1
        proof_of_work = '2375822353'
        
        hash_1_2 =  hashlib.sha256(Char_32t_Value(trans1).to_byte()+ Char_32t_Value(trans2).to_byte()).digest()
        hash_3_4 = hashlib.sha256(Char_32t_Value(trans3).to_byte() + Char_32t_Value(trans4).to_byte()).digest()
        merkle_hash = hashlib.sha256(hash_1_2 + hash_3_4 + Char_32t_Value(trans5).to_byte()).digest()

        updatedBlock =  hashlib.sha256(merkle_hash + Char_32t_Value(prev_block_hash).to_byte() + Uint32_t_Value(proof_of_work).to_byte()).digest()

        out = '\nBLOCK REPORT\n'
        prefix = '  '
        out += prefix + 'REPORT\n'
        out += prefix + '-' * 56+ '\n'
        prefix *= 2
        out += '{}{:32} block {}'.format(prefix, Char_32t_Value(block).to_hexa(), block_id) + '\n'
        out += '{}{:32} exist transaction'.format(prefix, Char_32t_Value(trans5).to_hexa()) + '\n'
        out += '{}{:32} manipulated transaction'.format(prefix, Char_32t_Value(manipulatedTrans5).to_hexa()) + '\n'
        out += '{}{:32} updated merkle {}'.format(prefix, UChar_32t(merkle_hash).to_hexa(), "updated merkle hash after hashing all transactions(5) in tree way") + '\n'
        out += '{}{:32} updated block hash {}'.format(prefix, UChar_32t(updatedBlock).to_hexa(), "updated block hash after hashing merkle root with proof of work & prev block") + '\n'
        out += '{} result: {}'.format(prefix,"the block will be rejected because of not exisitig the first 8 zeros in updated block") + '\n'

        return out
        
        
    def print_messages(cls, output_messages):
        response_message = output_messages.get_requested_message()
        
        for response_msg in response_message:
            if response_msg is not None:
                print(response_msg)
        
        extra_messages = output_messages.get_extra_messagees()
        
        for extra_message in extra_messages:
            if extra_message is not None:
                print(extra_message)

    def call(cls, request_bytes, command):     
        response_byte = cls.send(request_bytes)
        return MessageList(response_byte,command)
    
    def send(cls, msg):
        s.sendall(msg)
        log_success ("Client: Sent Succeeded")
        s.settimeout(1)
        response = bytearray()
        
        while True:
            try:
                message, address = s.recvfrom(1024)
                response += message       

            except socket.timeout:
                log_connection("timeout........")
                break;
        return response
           
class Request(object):
     
    def __init__(self, command, header_map, content_map):
        self.command = command
        self.content_map = content_map 
        self.header_map = header_map         
        self.request_in_bytes = b''
        self.checksum = b''
            
    def to_bytes(self): 
      all_bytes = b'' 
      header_bytes = b''  
      content_bytes = b'' 
      
      for key,value in self.content_map.items():          
          content_bytes += value.to_byte()
       
      for key,value in self.header_map.items():   
          header_bytes += value.to_byte()

      all_bytes += header_bytes
      self.checksum = checksum(content_bytes)
      all_bytes += self.checksum        
      all_bytes += content_bytes
      self.request_in_bytes = all_bytes   
      return all_bytes  

    def __str__(self):
        out = '\n{}MESSAGE\n'.format("Sending")
        out += '({}) {}\n'.format(len(self.request_in_bytes), self.request_in_bytes[:60].hex() + ('' if len(self.request_in_bytes) < 60 else '...'))
        prefix = '  '
        out += prefix + 'HEADER\n' 
        out += prefix + '-' * 56 + '\n'
        prefix *= 2

        for key,value in self.header_map.items():          
            out += '{}{:32} {} {}'.format(prefix,value.to_hexa(), key.value.display_name , str(value.to_value())) + '\n'
                  
        out += '{}{:32} {}'.format(prefix,self.checksum.hex(),Keys.CHECKSUM.value.display_name) + '\n'
        
        prefix = '  '
        out += '\n'
        out += prefix + self.command + '\n'
        out += prefix + '-' * 56 + '\n'
        prefix *= 2
                 
        for key,value in self.content_map.items():
            out += '{}{:32} {} {}'.format(prefix,value.to_hexa(), key.value.display_name , str(value.to_value())) + '\n'

        return out

        
class MessageList(object): 
    
    def __init__(self, message_bytes, requested_command):
        self.message_bytes = message_bytes
        self.requested_command = requested_command
        magic_bytes = Char_4t_Value(MAGIC).to_byte()
        messages = self.message_bytes.split(magic_bytes)
        self.extra_messages = []
        self.requested_message = []
        
        for message in messages:
            message = magic_bytes + message   
            command = self.message_header(message)
            
            if(requested_command == command):
                self.requested_message.append(MessageFactory(message).create())
            else:
                 self.extra_messages.append(MessageFactory(message).create())
            
        
    def message_header(self,message_bytes):
        return str(bytearray([b for b in message_bytes[4:16] if b != 0]), encoding='utf-8')
    
    def get_requested_message(self):
        return self.requested_message
    
    def get_extra_messagees(self):
        return self.extra_messages

        
class MessageFactory(object):
    
    def __init__(self, message_bytes):
        self.message_bytes = message_bytes
        
    def create(self):
        command = self.message_header(self.message_bytes)
        
        if command == Command.VERSION.value:
            return  VersionMessage(command, self.message_bytes)    
    
        elif (command == Command.VERACK.value or 
              command == Command.SEND_HEADERS.value or 
              command == Command.SEND_COMPCT.value or 
              command == Command.PING.value or 
              command == Command.ADDR.value or 
              command == Command.FEE_FILTER.value):
            return HeaderMessage(command, self.message_bytes)

        elif command == Command.INV.value:
            return InvMessage(command, self.message_bytes)
        
        elif command == Command.BLOCK.value:
            return BlockMessage(command, self.message_bytes)
        
    def message_header(self,message_bytes):
        return str(bytearray([b for b in message_bytes[4:16] if b != 0]), encoding='utf-8')
        
class Message(object): 
    
    def __init__(self, command, message_bytes):
        self.message_bytes = message_bytes
        self.content = []
        self.headers = {}
        self.command = command
 
    def __str__(self):
        msg = self.message_bytes
        out = '\n{}MESSAGE\n'.format("recieived" + ' ')
        out += '({}) {}\n'.format(len(msg), msg[:60].hex() + ('' if len(msg) < 60 else '...'))  
        self.message_header(msg[:24])
        
        prefix = '  '
        out += prefix + 'HEADER\n'
        out +=  prefix + '-' * 56 + '\n'
        prefix *= 2
        
        for key,value in self.headers.items():
           out += '{}{:32} {} {}'.format(prefix,value.to_hexa(), key.value.display_name , str(value.to_value())) + '\n'

        if len(self.content) != 0: 
            out += '\n'
            prefix = '  '
            out +=  prefix + self.command + '\n'
            out +=  prefix + '-' * 56 + '\n'
            prefix *= 2
            
            for key,value in self.content:
               out += '{}{:32} {} {}'.format(prefix,value.to_hexa(), key.value.display_name , str(value.to_value())) + '\n'
        return out;
    
    def message_header(self,header):
        magic, command_hex, payload_size, cksum = header[:4], header[4:16], header[16:20], header[20:]
        command = str(bytearray([b for b in command_hex if b != 0]), encoding='utf-8')
        #psz = Unmarshal_uint_Value(payload_size).tobytes()
        expected_cksum = checksum(self.message_bytes[24:])
        
        if expected_cksum is None:
            verified = ''
        elif expected_cksum == cksum:
            verified = '(verified)'
        else:
            verified = '(WRONG!! ' + expected_cksum.hex() + ')'
        
        self.headers.update({Keys.START_STRING: Byte_value(magic,''),
                              Keys.COMMAND: Byte_value(command_hex,command),
                              Keys.PAYLOAD: Unmarshal_uint_Value(payload_size), 
                              Keys.CHECKSUM: Byte_value(cksum, verified)})

    def get(self, key) :
        return self.content[key].to_value()


class VersionMessage(Message):

    def __init__(self, command, message_bytes):  
         self.message_bytes = message_bytes
         self.content = []
         self.headers = {}
         self.command = command
         self.__fill_map()
               
    def __fill_map(self):
        b = self.message_bytes[24:]
        
        version, my_services, epoch_time, your_services = b[:4], b[4:12], b[12:20], b[20:28]
        rec_host, rec_port, my_services2, my_host, my_port = b[28:44], b[44:46], b[46:54], b[54:70], b[70:72]
        nonce = b[72:80]

        time_str = strftime("%a, %d %b %Y %H:%M:%S GMT",gmtime(Unmarshal_int_Value(epoch_time).to_value()))
        print("timeeee: ", time_str)
        
        user_agent_size, uasz = Unmarshal_compactsize_Value(b[80:]).to_value()
        i = 80 + len(user_agent_size)
        user_agent = b[i:i + uasz]
        i += uasz
        start_height, relay = b[i:i + 4], b[i + 4:i + 5]
        
        self.content.extend([(Keys.VERSION, Unmarshal_int_Value(version)),
                             (Keys.SERVICE, Byte_value(my_services,'')),
                             (Keys.TIMESTAMP, Unmarshal_int_Value(epoch_time, time_str)),
                             (Keys.RECV_SERVICE, Byte_value(your_services,'')),
                             (Keys.RECV_IP, Ipv6_to_ipv4_value(rec_host)), 
                             (Keys.RECV_PORT, Unmarshal_uint_Value(rec_port)), 
                             (Keys.TRANS_SERVICE, Byte_value(my_services2,'')),
                             (Keys.TRANS_IP, Ipv6_to_ipv4_value(my_host)),
                             (Keys.TRANS_PORT, Unmarshal_uint_Value(my_port)),
                             (Keys.NONCE, Byte_value(nonce,'')), 
                             (Keys.USER_BYTES, Byte_value(user_agent_size,uasz)),
                             (Keys.USER_AGENT, Byte_value(user_agent,'')),
                             (Keys.HEIGHT, Unmarshal_uint_Value(start_height)), 
                             (Keys.RELAY, Byte_value(relay,''))])

class HeaderMessage(Message):

    def __init__(self, command, message_bytes):  
         self.message_bytes = message_bytes
         self.content = []
         self.headers = {}
         self.command = command

class InvMessage(Message):
    
    def __init__(self, command, message_bytes):  
         self.message_bytes = message_bytes
         self.content = []
         self.headers = {}
         self.command = command
         self.blocks = []
         self.__fill_map()
        
         
    def __fill_map(self):
         b = self.message_bytes[24:]
         count = b[:3]
         
         count_bytes, count_value = Unmarshal_compactsize_Value(count).to_value()
         
         self.content.extend([(Keys.COUNT, Byte_value(count_bytes,count_value))])
         
         msg = b[3:]
         
         while len(msg) != 0:
             type_b, hash_b = msg[:4], msg[4:36]
             
             type_bytes, type_value = Unmarshal_compactsize_Value(type_b).to_value()
             
             self.content.extend([(Keys.TYPE, Byte_value(type_bytes,TYPE_IDS[type_value])),
                                  (Keys.HASH, UChar_32t(hash_b))])
             
             if (Byte_value(type_bytes,type_value).to_hexa()== '02'):
                 self.blocks.append(UChar_32t(hash_b))
                 
             msg = msg[36:]

    def get_block(self,number):

        if len(self.blocks) < 499:
            return None
            
        return self.blocks[number]
        
class BlockMessage(Message):

    def __init__(self, command, message_bytes):  
         self.message_bytes = message_bytes
         self.content = []
         self.headers = {}
         self.command = command
         self.__fill_map()
         
    def __fill_map(self):
         b = self.message_bytes[24:]

         version, hash_b, root, timestamp, target, nonce  =  b[:4], b[4:36], b[36:68], b[68:72], b[72:76], b[76:80]
         count, trans_version, input_count , input_trans , index  = b[80:81], b[81:85], b[85:86], b[86:118], b[118:122]
         script_bytes, script, sequence = b[122:124], b[124:131], b[131:135]
         output_count, value, pk_script_bytes, pk_script, checksig, locktime =  b[135:136], b[136:144], b[144:145], b[145:211], b[211:212], b[212:]

         count_bytes, count_value = Unmarshal_compactsize_Value(count).to_value() 
         
         input_count_bytes, input_count_value = Unmarshal_compactsize_Value(input_count).to_value() 
         script_bytes_b, script_bytes_value = Unmarshal_compactsize_Value(script_bytes).to_value()
         pk_script_bytes_b, pk_script_bytes_value = Unmarshal_compactsize_Value(pk_script_bytes).to_value() 
         
         self.content.extend([(Keys.BLOCK_VERSION, Unmarshal_int_Value(version,'')),
                                  (Keys.PREV_HASH, UChar_32t(hash_b)),
                                  (Keys.MERKLE_ROOT, UChar_32t(root)),
                                  (Keys.UNIX, Unmarshal_uint_Value(timestamp)),
                                  (Keys.TARGET, Unmarshal_uint_Value(target,'')),
                                  (Keys.NONCE, Unmarshal_uint_Value(nonce,'')),
                                  (Keys.COUNT, Byte_value(count_bytes,count_value)),
                                  
                                  (Keys.VERSION, Unmarshal_int_Value(trans_version, '')),
                                  (Keys.INPUT_COUNT, Byte_value(input_count_bytes,input_count_value)),
                                  (Keys.OUTPOINT_HASH, UChar_32t(input_trans)),
                                  (Keys.OUT_INDEX, Unmarshal_uint_Value(index, '')),
                                  (Keys.SCRIPT_BYTES, Byte_value(script_bytes_b,script_bytes_value)),                                  
                                  (Keys.SCRIPT, Unmarshal_uint_Value(script,'')),
                                  (Keys.SEQUENCE, Unmarshal_uint_Value(sequence,'')),
                                  (Keys.OUTPUT_COUNT, Unmarshal_uint_Value(output_count)),
                                  (Keys.VALUE, Unmarshal_uint_Value(value)),
                                  (Keys.PK_SCRIPT_BYTES, Byte_value(pk_script_bytes_b,pk_script_bytes_value)),
                                  (Keys.PK_SCRIPT, Unmarshal_uint_Value(pk_script,'')),
                                  (Keys.OP_CHECKSIG, Unmarshal_uint_Value(checksig,'')),
                                  (Keys.LOCK_TIME, Unmarshal_uint_Value(locktime))])    

    
class Key:
    
        def __init__(self, displayName):
            self.display_name = displayName
               
        def get_display_name(self):
            return self.displayName
    
class Command(enum.Enum):
        VERSION = "version"
        VERACK = "verack"
        SEND_HEADERS = "sendheaders"
        PING = "ping"
        SEND_COMPCT = "sendcmpct"
        ADDR = "addr"
        FEE_FILTER = "feefilter"
        GETBLOCKS = "getblocks"
        INV = "inv"
        GETBLOCK = "getblocktxn"
        BLOCK = "block"

class Keys(enum.Enum):
        START_STRING = Key("magic")
        COMMAND = Key ("command")
        PAYLOAD = Key("payload")
        CHECKSUM = Key("checksum")
        
        VERSION = Key("version")
        SERVICE = Key("my Service")
        TIMESTAMP = Key("epoch time")
        RECV_SERVICE = Key("your services")
        RECV_IP = Key("your host")
        RECV_PORT = Key("your port")
        TRANS_SERVICE = Key("my services (again)")
        TRANS_IP = Key("my host")
        TRANS_PORT = Key("my port")
        NONCE = Key("nonce")
        USER_BYTES = Key("user agent")
        USER_AGENT = Key("user agent")
        HEIGHT = Key("start height")
        RELAY = Key("relay")
        
        HASH_COUNT = Key("hash count:")
        STOP_HASH = Key("stop hash")
        
        TYPE = Key("Type:")
        HASH = Key("Hash")
        
        COUNT = Key("count")
        BLOCK_HASH = Key("Block hash")
        INDEXES_LENGTH = Key("indexes length")
        INDEXES = Key("indexes")
        
        BLOCK_VERSION = Key("Block version")
        PREV_HASH = Key("Hash of previous block's header")
        MERKLE_ROOT = Key("Merkle root")
        UNIX = Key("Unix time:")
        TARGET = Key("target")
        
        INPUT_COUNT = Key("Number of inputs:")
        OUTPOINT_HASH = Key("Outpoint TXID")
        OUT_INDEX = Key("Outpoint index number")
        SCRIPT_BYTES = Key("Bytes in sig. script")
        SCRIPT = Key("signature")
        SEQUENCE = Key("Sequence number")
        
        OUTPUT_COUNT = Key("Number of outputs:")
        VALUE = Key("Satoshis:") 
        PK_SCRIPT_BYTES = Key("Bytes in pubkey script:")
        PK_SCRIPT = Key("pubkey script")
        LOCK_TIME = Key("locktime")
        OP_CHECKSIG = Key("OP_CHECKSIG")
  

def checksum(payload):
    hash1 = hashlib.sha256(payload).digest()
    hash2 = hashlib.sha256(hash1).digest()
    return hash2[:4]
        

class Byte_value(object):
     def __init__(self, byte_value, str_value):
        self.byte_value= byte_value
        self.str_value = str_value
        
     def to_byte(self):
        return self.byte_value
    
     def to_hexa(self):
         return self.byte_value.hex()
 
     def to_value(self):
        return self.str_value

class IValue:
    
    def to_byte(self):
        pass
    def to_hexa(self):
        pass
    def to_value(self):
        pass


class Hash_t(IValue):
    
    def __init__(self, value):
        self.value= value
        
    def to_byte(self):
        b_value = bytes.fromhex(self.value)
        return hashlib.sha256(b_value).digest()
    
    
    def to_hexa(self):
        return self.value
 
    def to_value(self):
        return ''

class UChar_32t(IValue) :
    
    def __init__(self, byte_value):
        self.byte_value= byte_value
        
    def to_byte(self):
        return self.byte_value
    
    
    def to_hexa(self):
        h = self.byte_value.hex()
        return "".join(reversed([h[i:i+2] for i in range(0, len(h), 2)]))
 
    def to_value(self):
        return ''    

class Int32_t_Value(IValue):
    
   def __init__(self, value):
        self.value= value    
    
   def to_byte(self):
       return int(self.value).to_bytes(4, byteorder='little', signed=True) 
   
   def to_hexa(self):
        return self.to_byte().hex()

   def to_value(self):
       return self.value

class Int64_t_Value(IValue):
    
   def __init__(self, value, str_value = None):
        self.value= value   
        self.str_value = str_value
    
   def to_byte(self):
       return int(self.value).to_bytes(8, byteorder='little', signed=True)
   
   def to_hexa(self):
        return self.to_byte().hex()

   def to_value(self):
       if self.str_value != None:
           return self.str_value
       return self.value

class Compactsize_t_Value(IValue):
    
     def __init__(self, value):
        self.value= value       
        
     def to_byte(self):   
        if self.value < 252:
            return Uint8_t_Value(self.value).to_byte()
        if self.value < 0xffff:
            return Uint8_t_Value(0xfd).to_byte() + Uint16_t_Value(self.value).to_byte()
        if self.value < 0xffffffff:
            return Uint8_t_Value(0xfe).to_byte() + Uint32_t_Value(self.value).to_byte()
        return Uint8_t_Value(0xff).to_byte() + Uint64_t_Value(self.value).to_byte()

     def to_hexa(self):
        return self.to_byte().hex()

     def to_value(self):
       return self.value


class Compactsize_t_a_Value(IValue):
    
     def __init__(self, values):
        self.values= values
        
        
     def to_byte(self):  
         r = b''
         for value in self.values:
             r += Compactsize_t_Value(value) .to_byte()       
         return r

     def to_hexa(self):
        return self.to_byte().hex()

     def to_value(self):
       return self.values

class Uint8_t_Value(IValue):
  
   def __init__(self, value):
        self.value= value
    
   def to_byte(self):
       return int(self.value).to_bytes(1, byteorder='little', signed=False)
   
   def to_hexa(self):
        return self.to_byte().hex()

   def to_value(self):
       return self.value
   
    
class Uint16_t_Value(IValue):
   
   def __init__(self, value):
        self.value= value
    
   def to_byte(self):
       return int(self.value).to_bytes(2, byteorder='little', signed=False)
   
   def to_hexa(self):
        return self.to_byte().hex()

   def to_value(self):
       return self.value
    
class Uint32_t_Value(IValue):
    
   def __init__(self, value):
        self.value= value
    
   def to_byte(self):
       return int(self.value).to_bytes(4, byteorder='little', signed=False)
   
   def to_hexa(self):
        return self.to_byte().hex()

   def to_value(self):
       return self.value 
   
   
class Uint64_t_Value(IValue):
    
   def __init__(self, value):
        self.value= value
    
   def to_byte(self):
       return int(self.value).to_bytes(8, byteorder='little', signed=False)
   
   def to_hexa(self):
        return self.to_byte().hex()

   def to_value(self):
       return self.value  
    
class Unmarshal_int_Value(IValue):
    
   def __init__(self, bvalue, str_value = None):
        self.bvalue= bvalue
        self.str_value = str_value
    
   def to_byte(self):
       return self.bvalue
   
   def to_hexa(self):
        return self.bvalue.hex()

   def to_value(self):
       if self.str_value != None:
           return self.str_value
       
       return int.from_bytes(self.bvalue, byteorder='little', signed=True)
 
 
class Unmarshal_uint_Value(IValue):
    
   def __init__(self, bvalue, str_value = None):
        self.bvalue= bvalue
        self.str_value = str_value
    
   def to_byte(self):
        return self.bvalue
   
   def to_hexa(self):
        return self.bvalue.hex()

   def to_value(self):
        if self.str_value != None:
           return self.str_value
       
        return int.from_bytes(self.bvalue, byteorder='little', signed=False)

class Unmarshal_compactsize_Value(IValue):
    
   def __init__(self, bvalue):
       self.bvalue = bvalue
    
   def to_byte(self):
        return self.bvalue
   
   def to_hexa(self):
        return self.to_byte().hex()

   def to_value(self):
        b = self.bvalue
        key = b[0]
        if key == 0xff:
            return b[0:9], Unmarshal_uint_Value(b[1:9]).to_value()
        if key == 0xfe:
            return b[0:5], Unmarshal_uint_Value(b[1:5]).to_value()
        if key == 0xfd:
            return b[0:3], Unmarshal_uint_Value(b[1:3]).to_value()
        return b[0:1], Unmarshal_uint_Value(b[0:1]).to_value()
    
class Ipv6_to_ipv4_value(IValue):
    
   def __init__(self, bvalue):
        self.bvalue= bvalue
    
   def to_byte(self):
       return self.bvalue
   
   def to_hexa(self):
        return self.bvalue.hex()

   def to_value(self):
       ipv6 = self.bvalue
       return '.'.join([str(b) for b in ipv6[12:]])
   
    
class Ipv6_from_ipv4_Value(IValue):
    
   def __init__(self, value):
        self.value= value
    
   def to_byte(self):
       ipv4_str = self.value
       pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
       return pchIPv4 + bytearray((int(x) for x in ipv4_str.split('.')))
   
   def to_hexa(self):
        return self.to_byte().hex()

   def to_value(self):
       return self.value 

class Empty_Value(IValue):
     def __init__(self, value):
        self.value= value
        
     def to_byte(self):
        return b''
    
     def to_hexa(self):
         return ''
 
     def to_value(self):
        return self.value 
   
class Char_4t_Value(IValue):
    
     def __init__(self, value):
        self.value= value
        
     def to_byte(self):
        to_str = '{:08x}'.format(self.value)
        return bytes.fromhex(to_str)
    
     def to_hexa(self):
         return '{:08x}'.format(self.value)
 
     def to_value(self):
        return ''

class Char_32t_Value(IValue) :
    
    def __init__(self, value):
        self.value= value
        
    def to_byte(self):
        return self.value.to_bytes(32, byteorder="little")
    
    
    def to_hexa(self):
        return self.value.to_bytes(32, byteorder="little").hex()
 
    def to_value(self):
        return ''  
 
class String_Value(IValue):
     def __init__(self, value):
        self.value= value
        
     def to_byte(self):
        return bytes.fromhex(self.to_hexa())
    
     def to_hexa(self):
        enc = self.value.encode('utf-8')
        h = enc.hex()
        diff = 24 - len(h) 

        padding = '0'
        
        for i in range(diff - 1):
            padding += '0'
            
        return enc.hex() + padding
 
     def to_value(self):
        return self.value

class Zero_fill_Value(IValue):
     def __init__(self, value, size):
        self.value= value
        self.size = size
        
     def to_byte(self):
         data = bytearray([0])
         data.extend(repeat(self.value, self.size))
         return data
    
     def to_hexa(self):
         return self.to_byte().hex()

     def to_value(self):
        return self.value    
    
def log_client(*message):
    log_console("CLIENT", message)

def log_success(*message):
    log_console("SUCCESS", message)

def log_connection(*message):
    log_console("Connection", message)

def log_console(log_type, *message):
    if (log_type == "Connection") :
        print("\033[0;35m", datetime.datetime.now(), message, "\033[0;00m")
    elif (log_type == "SUCCESS") : 
        print("\033[0;32m", datetime.datetime.now(), message, "\033[0;00m")
    elif(log_type == "CLIENT") : 
        print("\033[0;36m", datetime.datetime.now(), message, "\033[0;00m")
    else :
        print(datetime.datetime.now()," ] ", message)        
        
if __name__ == '__main__':      
     su_id = int(sys.argv[1]) % MAX_BLOCK_NUMBER
     client = Lab5(su_id)
     client.start()