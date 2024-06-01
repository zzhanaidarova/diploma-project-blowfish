var Blowfish = function(key, mode) { 

  this.key = key;
  this.mode = "cbc";
  
  this.sBox0  = Blowfish.sBox0.slice();
  this.sBox1  = Blowfish.sBox1.slice();
  this.sBox2  = Blowfish.sBox2.slice();
  this.sBox3  = Blowfish.sBox3.slice();
  this.pArray = Blowfish.pArray.slice();
  
  this.generateSubkeys(key);
};
  
  Blowfish.prototype = {

    sBox0: null,
    sBox1: null,
    sBox2: null,
    sBox3: null,
    pArray: null,
    key: null,
    mode: "cbc",
    iv:  "hello123",
    keyStr: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",

    encrypt: function(string) {
      string = this.utf8Decode(string);
      var blocks = Math.ceil(string.length/8);
  
      var ivL, ivR, ivLivR;
      ivLivR = this.split64by32(iv);
      ivL = ivLivR[0];
      ivR = ivLivR[1];
  
      var encryptedString = "";
      for (var i = 0; i < blocks; i++) {
        var block = string.substr(i * 8, 8);
        if (block.length < 8) {
          var count = 8 - block.length;
          while (0 < count--) {
            block += "\0";
          }}  
        var xL, xR, xLxR;
        xLxR = this.split64by32(block);
        xL = xLxR[0];
        xR = xLxR[1];
  
        xL = this.xor(xL, ivL);
        xR = this.xor(xR, ivR);
  
        xLxR = this.encipher(xL, xR);
        xL = xLxR[0];
        xR = xLxR[1];
  
        ivL = xL;
        ivR = xR;
        encryptedString += this.num2block32(xL) + this.num2block32(xR);
      }
      return encryptedString;
    },

    decrypt: function(string, iv) {
      var blocks = Math.ceil(string.length/8);
      var ivL, ivR, ivLtmp, ivRtmp, ivLivR;
      ivLivR = this.split64by32(iv);
      ivL = ivLivR[0];
      ivR = ivLivR[1];
      var decryptedString = "";
      for (var i = 0; i < blocks; i++) {
        var block = string.substr(i * 8, 8);
        var xL, xR, xLxR;
        xLxR = this.split64by32(block);
        xL = xLxR[0];
        xR = xLxR[1];
        ivLtmp = xL;
        ivRtmp = xR;
        xLxR = this.decipher(xL, xR);
        xL = xLxR[0];
        xR = xLxR[1];
        xL = this.xor(xL, ivL);
        xR = this.xor(xR, ivR);
        ivL = ivLtmp;
        ivR = ivRtmp;
        decryptedString += this.num2block32(xL) + this.num2block32(xR);
      }
      decryptedString = this.utf8Encode(decryptedString);
      return decryptedString;
    },

    F: function(xL) {
      var a = xL >>> 24;
      var b = xL << 8 >>> 24;
      var c = xL << 16 >>> 24;
      var d = xL << 24 >>> 24;
  
      var res = this.addMod32(this.sBox0[a], this.sBox1[b]);
      res = this.xor(res, this.sBox2[c]);
      res = this.addMod32(res, this.sBox3[d]);
      return res;
    },
    
    encipher: function(xL, xR) {
      var tmp;
      for (var i = 0; i < 16; i++) {
        xL = this.xor(xL, this.pArray[i]);
        xR = this.xor(this.F(xL), xR);
        tmp = xL;
        xL = xR;
        xR = tmp;
      }
  
      tmp = xL;
      xL = xR;
      xR = tmp;
  
      xR = this.xor(xR, this.pArray[16]);
      xL = this.xor(xL, this.pArray[17]);
  
      return [xL, xR];
    },
    decipher: function(xL, xR) {
      var tmp;
  
      xL = this.xor(xL, this.pArray[17]);
      xR = this.xor(xR, this.pArray[16]);
  
      tmp = xL;
      xL = xR;
      xR = tmp;
  
      for (var i = 15; i >= 0; i--) {
        tmp = xL;
        xL = xR;
        xR = tmp;
        xR = this.xor(this.F(xL), xR);
        xL = this.xor(xL, this.pArray[i]);
      }
  
      return [xL, xR];
    },
  
    generateSubkeys: function(key) {
      var data = 0;
      var k = 0;
      var i, j;
      for (i = 0; i < 18; i++) {
        for (j = 4; j > 0; j--) {
          data = this.fixNegative(data << 8 | key.charCodeAt(k));
          k = (k + 1) % key.length;}
        this.pArray[i] = this.xor(this.pArray[i], data);
        data = 0;}
        
      var block64 = [0, 0];
      for (i = 0; i < 18; i += 2) {
        block64 = this.encipher(block64[0], block64[1]);
        this.pArray[i] = block64[0];
        this.pArray[i + 1] = block64[1];}
  
      for (i = 0; i < 256; i += 2) {
        block64 = this.encipher(block64[0], block64[1]);
        this.sBox0[i] = block64[0];
        this.sBox0[i + 1] = block64[1];}
  
      for (i = 0; i < 256; i += 2) {
        block64 = this.encipher(block64[0], block64[1]);
        this.sBox1[i] = block64[0];
        this.sBox1[i + 1] = block64[1];}
  
      for (i = 0; i < 256; i += 2) {
        block64 = this.encipher(block64[0], block64[1]);
        this.sBox2[i] = block64[0];
        this.sBox2[i + 1] = block64[1];}
  
      for (i = 0; i < 256; i += 2) {
        block64 = this.encipher(block64[0], block64[1]);
        this.sBox3[i] = block64[0];
        this.sBox3[i + 1] = block64[1];}
    },
  

    block32toNum: function(block32) {
      return this.fixNegative(
        block32.charCodeAt(0) << 24 |
        block32.charCodeAt(1) << 16 |
        block32.charCodeAt(2) << 8 |
        block32.charCodeAt(3)
        );
    },
  

    num2block32: function(num) {
      return String.fromCharCode(num >>> 24) +
      String.fromCharCode(num << 8 >>> 24) +
      String.fromCharCode(num << 16 >>> 24) +
      String.fromCharCode(num << 24 >>> 24);
    },
  
    xor: function(a, b) {
      return this.fixNegative(a ^ b);
    },
  
    addMod32: function(a, b) {
      return this.fixNegative((a + b) | 0);
    },
  
    fixNegative: function(number) {
      return number >>> 0;
    },
  
    split64by32: function (block64) {
      var xL = block64.substring(0, 4);
      var xR = block64.substring(4, 8);
  
      return [this.block32toNum(xL) , this.block32toNum(xR)];
    },
  
    utf8Decode: function(string) {
      var utftext = "";
      for (var n = 0; n < string.length; n++) {
        var c = string.charCodeAt(n);
        if (c < 128) {
          utftext += String.fromCharCode(c);
        } else if (c > 127 && c < 2048) {
          utftext += String.fromCharCode(c >> 6 | 192);
          utftext += String.fromCharCode(c & 63 | 128);
        } else {
          utftext += String.fromCharCode(c >> 12 | 224);
          utftext += String.fromCharCode(c >> 6 & 63 | 128);
          utftext += String.fromCharCode(c & 63 | 128);
        }
      }
      return utftext;
    },
  
    utf8Encode: function (utftext) {
      var string = "";
      var i = 0;
      var c = 0;
      var c1 = 0;
      var c2 = 0;
  
      while ( i < utftext.length ) {
  
        c = utftext.charCodeAt(i);
  
        if (c < 128) {
          string += String.fromCharCode(c);
          i++;
        } else if((c > 191) && (c < 224)) {
          c1 = utftext.charCodeAt(i+1);
          string += String.fromCharCode(((c & 31) << 6) | (c1 & 63));
          i += 2;
        } else {
          c1 = utftext.charCodeAt(i+1);
          c2 = utftext.charCodeAt(i+2);
          string += String.fromCharCode(((c & 15) << 12) | ((c1 & 63) << 6) | (c2 & 63));
          i += 3;
        }
  
      }
  
      return string;
    },
  
    base64Encode : function (input) {
      var output = "";
      var char1, char2, char3, enc1, enc2, enc3, enc4;
      var i = 0;
  
  
      while (i < input.length) {
        char1 = input.charCodeAt(i++);
        char2 = input.charCodeAt(i++);
        char3 = input.charCodeAt(i++);
  
        enc1 = char1 >> 2;
        enc2 = ((char1 & 3) << 4) | (char2 >> 4);
        enc3 = ((char2 & 15) << 2) | (char3 >> 6);
        enc4 = char3 & 63;
  
        if (isNaN(char2)) {
          enc3 = enc4 = 64;
        } else if (isNaN(char3)) {
          enc4 = 64;
        }
  
        output = output + this.keyStr.charAt(enc1) + this.keyStr.charAt(enc2) + this.keyStr.charAt(enc3) + this.keyStr.charAt(enc4);
      }
  
      return output;
    },
  
    base64Decode : function (input) {
      var output = "";
      var char1, char2, char3;
      var enc1, enc2, enc3, enc4;
      var i = 0;
  
      input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");
  
      while (i < input.length) {
  
        enc1 = this.keyStr.indexOf(input.charAt(i++));
        enc2 = this.keyStr.indexOf(input.charAt(i++));
        enc3 = this.keyStr.indexOf(input.charAt(i++));
        enc4 = this.keyStr.indexOf(input.charAt(i++));
  
        char1 = (enc1 << 2) | (enc2 >> 4);
        char2 = ((enc2 & 15) << 4) | (enc3 >> 2);
        char3 = ((enc3 & 3) << 6) | enc4;
  
        output = output + String.fromCharCode(char1);
  
        if (enc3 != 64) {
          output = output + String.fromCharCode(char2);
        }
        if (enc4 != 64) {
          output = output + String.fromCharCode(char3);
        }
      }
      return output;
    },
  
    trimZeros: function(input) {
      return input.replace(/\0+$/g, "");
    }
  }
  
  Blowfish.pArray = [
    0x12345678, 0x23456789, 0x34567890, 0x45678901, 0x56789012, 0x67890123,
    0x78901234, 0x89012345, 0x90123456, 0xa0123456, 0xb1234567, 0xc2345678,
    0xd3456789, 0xe4567890, 0xf5678901, 0x01234567, 0x12345678, 0x23456789];
  
Blowfish.sBox0 = [  
  0x8D042863, 0xC4A78D9C, 0xAE3010DD, 0x72495937, 0x3C717F25, 0x78CFF096, 0x7ACAABFB, 0x145A18CD, 
  0xE21C6BEE, 0x267E7BE1, 0x530A0641, 0x64D7FAE8, 0x10BB9C23, 0xA9EE669C, 0x0EDBD70E, 0x87BD1814,
  0x16F20A10, 0x73629C3D, 0xA61B692B, 0x3A600845, 0x5D29348E, 0x659694DF, 0xF8FF3C18, 0x4E3A0B06,
  0xC2889891, 0xC7530852, 0xD6268D2C, 0x7D48178D, 0xE8756B2D, 0x9B65ED36, 0xF8AF7679, 0xFA844B11,
  0x8BAA10C7, 0x61294401, 0x868B2DB3, 0xBFAFA3DD, 0xE442F20B, 0x05D57445, 0x24AEB5DD, 0x1C38F0C3,
  0x6FDBF2F0, 0xF581CC68, 0x2023F884, 0x98573F2C, 0xA5B96DD7, 0x4E89BFE9, 0xF902BE6E, 0x29C094A9,
  0xEA8EF0AD, 0xE6DE242B, 0xAD0EC8DC, 0xADE0CE28, 0x23FAA576, 0x1827BD4C, 0xA54DF833, 0x6905505F,
  0x7464029E, 0x17078F7A, 0xC35CD48D, 0xC336F7C1, 0x8E704A1F, 0x5A11BC80, 0xCAA0A0E8, 0x05D16971,
  0x0AA7188D, 0xB93AF93A, 0x74435429, 0xD7F44584, 0x5181E628, 0xBF2B682B, 0xBC79555F, 0x96F46A1E,
  0xB2339705, 0xE3327C67, 0xFCA22519, 0x81ECC769, 0x1A339A5E, 0x6101B470, 0xDFDB9E06, 0x7E700805,
  0xD894F5F3, 0x9FE80708, 0xCCEB01A9, 0xE1754E83, 0xB20236BD, 0xAD620C63, 0x1CB768B7, 0x2C4CC6EE,
  0xEF682F7E, 0x4EA7AB3E, 0x3710ADCA, 0x9B0B11F5, 0xC769870F, 0x9269D401, 0x2CB819AE, 0xA6380244,
  0x15F73144, 0x21385C98, 0x03E13A9F, 0xCACC0A3A, 0x55A84C5F, 0xBA8E4D33, 0xD0827DBF, 0x1748FAF0,
  0xF5A3DEC5, 0xC7CF4B6D, 0x7DE27F3D, 0x8542DC13, 0x6EEDB102, 0xD0D1BDDC, 0xBC74E2DA, 0xBB60E0FB,
  0xEC96AD2F, 0x496877DB, 0xFEDFDA1E, 0xAC7CE90F, 0x6B3A150D, 0x7FFEAB39, 0xBA8712B7, 0x6365DB76,
  0xEC407674, 0x90821E45, 0x29128CF2, 0x1116E8C8, 0x16731B72, 0xB491DA8F, 0x4F0693FE, 0x9BE2EDA0,
  0x871E7F9A, 0x3266BE74, 0x741A60F2, 0x7A698083, 0x68FC0F6C, 0xA6356AEA, 0x01A145D4, 0x244499FA,
  0xDD506480, 0xE305BEEA, 0xBAE7E509, 0xB85633E4, 0xDEB0D029, 0x3D345EAD, 0xD50DD84C, 0x99F12065,
  0x6E8D5D2F, 0xF06D0D88, 0x7EB43537, 0x1A10DC17, 0x36DF7687, 0x0BEC2B4D, 0x5F5D74E9, 0x52258AA4,
  0x501D896E, 0x9303263E, 0x7A5154F6, 0x963B1AD8, 0x73D2F682, 0x1AD9EAE5, 0xAC43170E, 0x47BC77BC,
  0xF95E53DC, 0x17AA1C48, 0xD8D2865C, 0x4B4A55EB, 0x97D77B9B, 0x30AFE59B, 0x7E1DAD6D, 0xCE8FA24F,
  0xA1504C17, 0xC2BC30BF, 0xAF2131F3, 0x7C6BCE6A, 0x5EC3B155, 0x6ACD4A77, 0xE3628217, 0xC01C64EE,
  0x4E67735D, 0xBC4500A5, 0x091CC7F1, 0x243251F5, 0x43C017AF, 0xC088A025, 0x9BBD32A7, 0xC9CB1BA5,
  0x8E778A49, 0x062F4423, 0xB0551A9E, 0x9FDA62D4, 0x891036E4, 0x0AD2C99A, 0x447EA3E7, 0x2B193E56,
  0x132BE567, 0x6A988F75, 0xD2DAC50A, 0x5419A518, 0x25AD7805, 0xF6660203, 0xDC74F99F, 0xF7E2828C,
  0x14F5F23A, 0x06BE613A, 0x572323AD, 0x4F62BECD, 0xFB99DE34, 0xCB70FDAA, 0x24055CED, 0xF67E958A,
  0xB9DEF534, 0x4FA44BB1, 0xA0385634, 0x53044463, 0x628D52F2, 0xE1AFD2C1, 0xBEB8CBD3, 0xEDDD9185,
  0xEF7EFBE1, 0x04AE1D47, 0x7FD440F4, 0x8F513D30, 0x84321A29, 0x0BE2AB19, 0xC4200DCF, 0xAF13CB1B,
  0xE85D9056, 0x798A0036, 0x2E6BEA8D, 0x2D522874, 0xF55C22EC, 0x1C80D72F, 0xB8D032E8, 0x21412F59,
  0x6F91DBA1, 0x8B4BF5CD, 0x64C4C0FE, 0x5271F404, 0x26E9BC2A, 0x7503F69F, 0x824DF099, 0x1BBAC246,
  0x6EC9DC81, 0x1F55BEC4, 0x2C300DB2, 0xD67CCBCA, 0x45BE7A8B, 0x3F1D3234, 0x0CF9E569, 0xB468F718,
  0xD74A4ED3, 0xA17163CF, 0x5337205D, 0x572C469A, 0xCFE3EDF9, 0xED3CA4D9, 0x6438AEC5, 0x4DF40C7C];
  
Blowfish.sBox1 = [  
  0xA8096AF4, 0x0E2336EF, 0x87AE9F4D, 0xEFF04642, 0x3B5D9B71, 0x0E012FE5, 0xC494D37C, 0xB060873F, 
  0x5EC99265, 0x5B34CC55, 0xD14435B5, 0xEC06A2EF, 0xAEDE257F, 0xAA836E2E, 0x42B2A632, 0xFD4E6C9B, 
  0x8515937B, 0x871DBA01, 0x18B2304E, 0xB609C4A0, 0xB1910B3B, 0x665BA07A, 0x02C80201, 0x3EF7C53F, 
  0x33F2EB22, 0x9BEFA3F7, 0xE9F2B985, 0x293438BC, 0x6D5CB990, 0xFDC22E79, 0xA8097C6B, 0xD4327635, 
  0x04B18058, 0xC56EE6EF, 0x47CB4BC8, 0xAFE667A1, 0x0F7ADB9B, 0x04A05066, 0xB8BEDE7A, 0x49191CEA, 
  0xE7D26459, 0x9B6BBFFD, 0x90D884A3, 0x7B75FDAB, 0x2A5A995A, 0x3F8F7213, 0x4EADEDD6, 0x1A8BE48E, 
  0x17D1A381, 0x405DD38B, 0x3B76F521, 0x98363CB4, 0x570E41E9, 0xFA001E01, 0x11AC6FB5, 0x72AB7A5A, 
  0xC04E5197, 0xF495118C, 0x24FB1226, 0xF96FBC20, 0x24A681AC, 0x103C0345, 0x0477B9B9, 0x780CC721, 
  0xE6A4AAD5, 0x4D320A11, 0x646F8BD8, 0x01BB4F38, 0xEF49AF4F, 0xCBA1F5DB, 0x1615B908, 0x06A6E6DD, 
  0x3BC4F2AA, 0x08CFEBA8, 0x6E094BB1, 0x788A7453, 0xB8DB8030, 0xC96D65EE, 0xB85F7BDB, 0x72FA77AB, 
  0xDD2B8EFE, 0x291F8EC0, 0xC7D388A1, 0xB301FBF3, 0x6C0A5D5D, 0x2D5C3DB5, 0xF44D00F3, 0x7A1DB8C6, 
  0x16941137, 0x146BDA36, 0x6674C914, 0x995C18A3, 0x123F9B6A, 0xA805EA5D, 0x061DF315, 0x6853DDA3, 
  0xAA5502CC, 0x32F95960, 0xD1B5EAE8, 0x3C3EC259, 0x8E4E2065, 0x9EAA9F3A, 0x4F93193E, 0xA5BCB3AF, 
  0x6F10E552, 0xD0D1C574, 0xDCEEAEC5, 0x06277914, 0x153FFDED, 0x10C44FC5, 0x57714B82, 0x10220A1D, 
  0x9C9EE7DF, 0x308BF41D, 0x66FE1086, 0x9A5383E7, 0x950B1AFB, 0x69BF3AB8, 0x1DBE936B, 0xF2F0B44D, 
  0x5D689697, 0x939CB209, 0x24EFB6ED, 0x68F1A6E3, 0xD58EF715, 0x335132DC, 0x27F29C2F, 0x2F5E0CE5, 
  0x614DE3A9, 0xF64371FD, 0xCC088A16, 0xEB9DCD6A, 0x78A227F7, 0x27501C41, 0x1CBEC2B2, 0xC87EE0C9, 
  0x55C5612E, 0x7FB1FFCD, 0xBE54614B, 0x5EE0F5AE, 0x0B018F0B, 0x36B5F894, 0xCEC1D3DB, 0x41CCB811, 
  0xE9919B64, 0x0112663D, 0x290690AA, 0x357FE013, 0xB3D76483, 0xC5D0172D, 0x63510996, 0xA4EA72FF, 
  0x6636827E, 0x01F24040, 0xF1D14716, 0x93810B87, 0x41CD94F0, 0xCED33F8B, 0xCDBBDDA1, 0x0FA58F62, 
  0x96BFBE1F, 0xD1835CD9, 0x7C5790A5, 0x1C6287E6, 0x487EBD73, 0x059DE06D, 0x00FF4115, 0xC733469D,
  0xD2DD9222, 0xCB458FF2, 0x482B4047, 0x35E3DB41, 0x58921448, 0xA764A6B8, 0xFCE0E943, 0xBD7C2067,
  0x796DCCDB, 0x50C79DF1, 0x071C6E04, 0xEFE2905D, 0xE0A19962, 0x72FD9682, 0xE43720AE, 0xD3A17B7F,
  0xD89FAED4, 0xA9968DF5, 0x74009BB2, 0xB50730FA, 0x20C8A04B, 0x6EED8D3C, 0xCA6967E2, 0x8E19613A,
  0x1AEAC134, 0x5DCE6F16, 0x34CF43A2, 0x86C6131E, 0x733114C4, 0x2D9E183D, 0xC6C63E20, 0xEA3D7437,
  0xF7B61C05, 0x81440AD4, 0x5086C299, 0xC3F60874, 0x6EDC5EC5, 0x9D909C4F, 0x581ABDFC, 0x76C2DB4F,
  0x1AE5ECC5, 0xE4E2D5D3, 0xE1056EF1, 0x6D7F7DA5, 0x59E7247F, 0x27D74B4D, 0x7C1FE9F7, 0xE09FB04D,
  0x06A82BEC, 0x3F0E696F, 0x85948C00, 0x6B2FC483, 0x1480D4B6, 0x1311CF34, 0x1CAB8C9D, 0x66F6F3B2,
  0x356868A7, 0xD290B3F7, 0x5EF33606, 0x861C38FF, 0x1DBB5806, 0xD525DBBA, 0x25FC8EBE, 0x0C06D71C,
  0x47E7F514, 0x06084CB2, 0x2A87A74C, 0xF7BA04A3, 0x8013091F, 0x567090FA, 0x5EBAC093, 0xC1C24798,
  0x2FE9518D, 0x368B534C, 0x776A596B, 0xD1EEE6FC, 0x5807C39A, 0x166C6EDA, 0x002196CE, 0x4B75A45C,
  0xF037D73E, 0xFFDB26EC, 0x4524370B, 0x81779207, 0x111EC543, 0x771AD9C2, 0x9111BE16, 0x8BC1D647];
  
Blowfish.sBox2 = [
  0x0E2FB39E, 0xAC0EFFEF, 0x565B8CCC, 0x1F75E051, 0x3E847A83, 0xB4CEFE0C, 0xC76169D3, 0xD41BEEED, 
  0x775C8471, 0xE25CBA99, 0x273BE9BC, 0x15E9EB1D, 0x66A6FD70, 0xE9308D96, 0xD972C201, 0x7BED5033,
  0x402E4C72, 0x3F890C94, 0xE53C7FB7, 0x29A9015F, 0x13E6CCF4, 0xA6EE9380, 0xD5776D98, 0x21BB536B,
  0xB16CF31E, 0x596B66C4, 0x01FAAC01, 0x2140E258, 0xEDFE4F1A, 0x67E4008C, 0x648E4499, 0x78DC4911,
  0x648E02F1, 0x434C412A, 0xBD3C2E36, 0xFDDCBA4A, 0xE865AC2A, 0xB7DCEACD, 0x48727ED0, 0x373FF345,
  0xA77DCDD0, 0xC2D8F4B2, 0xEC7DAF57, 0xB708929D, 0xC4C268DE, 0x60D7F3F3, 0x6D0EEFCA, 0xE01E004B,
  0x4FF3B0A8, 0x3583421C, 0x9224067A, 0x9C56F66C, 0x7AE3ECEB, 0x88C45442, 0xAC5A60E1, 0xEDFC76FB,
  0xCAA21EF1, 0x9266B6F8, 0x4E80FA92, 0x246B042A, 0x1A88B1DC, 0x231E28DA, 0x96BA4F72, 0xC21CC742,
  0x203F3C17, 0x04982FA1, 0x49DE6877, 0x3E5B62C1, 0x0F2D5B43, 0x767766B0, 0x4209AD8C, 0xBE9559DB,
  0x693D422A, 0x27858D84, 0x6BF6C3D4, 0xC4AE23B3, 0xDD339837, 0xFF32469E, 0xB4C50A97, 0xE5A17CE8,
  0x01B4418F, 0x048AFE99, 0xACFFA7C0, 0x326ED5C9, 0x7553227B, 0xF555E9E9, 0x4E61B6E1, 0xC534F37B,
  0x9E5883DC, 0xD43208B6, 0x64F51033, 0xA99717BA, 0x7260B9C0, 0xE5621119, 0x4281B079, 0xB3194C69,
  0x118BC849, 0xDF3129CD, 0xB4C99B89, 0x30BE20EB, 0x13C758E1, 0xA5428192, 0xA95C3254, 0x02A27E58,
  0x30D6FEF9, 0x638F8E06, 0xFC294A7E, 0x65729588, 0xDAB4CAB4, 0x4812B037, 0xCC1C777F, 0xA678967F,
  0x98F04680, 0x76F1716A, 0x8BF72F37, 0x8E7C320D, 0xD36E01C5, 0x4A7A6ED4, 0x51647DCE, 0xF54AD95B,
  0xECF68B55, 0xC2A16858, 0xC6A0F547, 0xB5B7A32F, 0xF182028D, 0x16E1C54B, 0x66DCE683, 0x1D59E3D6,
  0x7FED343B, 0x0558DB24, 0xED19F38E, 0xD6593D80, 0x42C412A5, 0x0DF431F9, 0x162C7848, 0x1810108F,
  0x5F1A1768, 0x3A0061CF, 0xD992B2DE, 0xA74323C1, 0xE41DD71A, 0x62AF54DC, 0x0BB1D92E, 0x86E63B3F,
  0xB22CC0E0, 0xBDE1C59F, 0x7896A015, 0x682BFA75, 0x4B13DE44, 0x9FBC8922, 0x82CB6294, 0xBDEC0C5C,
  0x5A154B02, 0x289AAF8A, 0x7A045CFE, 0xBB2EE048, 0x3346434F, 0x9ADAC462, 0x06C4612A, 0xB60A3DA7,
  0xC2353B2A, 0x3713E2B0, 0x75EB5A1D, 0x5686A338, 0x18FBC8F1, 0xAD110662, 0x8278731A, 0xD0890C9F,
  0x87395BCD, 0xBE9DE826, 0x161EB81E, 0x99039A9B, 0x0F61A15D, 0xFF9312D5, 0x30E2008E, 0x5B5AA26F,
  0x8E9DF34A, 0x75A48528, 0x543BC045, 0x9908D533, 0xD535800F, 0xBF2B66D7, 0x20140E92, 0xE8E2A8A7,
  0xADDCDFD9, 0x854E56D6, 0x2FE9535A, 0x731A57AC, 0x49AA9EBB, 0x520854B0, 0x141853D8, 0x2444D304,
  0xD643C7EF, 0x1D24078F, 0x03997BCF, 0xFA7CCC1E, 0x9C7887E8, 0xA0BE0DF1, 0x0FB11B3F, 0x6F40FEBF,
  0x48454DC3, 0x04CE085C, 0x0BA84314, 0x8E625C52, 0xECB49A83, 0x2A1FC296, 0xA326C48C, 0xBBC933A5,
  0xAC13B4BA, 0x9BD4FDA6, 0xE0859AFC, 0xF5D2E270, 0xC94A79A3, 0x86E14735, 0xCF9CBD38, 0x8CBA7F00,
  0x794C005C, 0x2DF5E8E7, 0x1BD3F82A, 0xA132ACB1, 0x654E45BC, 0x9FBFAEF4, 0x159D96F3, 0xFE2F7C44,
  0xE7832800, 0xE488305C, 0x63D78A20, 0x9130563F, 0x6EDB6E07, 0xDCA80504, 0x3C68D189, 0x4E222D1A,
  0xDC5F3B7A, 0x22610153, 0x46BBC18A, 0x4A0B766E, 0xCD05AF9B, 0x8D43302A, 0xF4D53B63, 0xA700F7A1,
  0x08CBA6CD, 0xE0A66D6B, 0x946E7F04, 0x29BCC1CB, 0xD127B737, 0xEA475438, 0x69DCEA48, 0x50CE9D69,
  0x0D2C4E00, 0xF4DC42B5, 0x07AC08E0, 0x5469D622, 0xA1B810FB, 0xE62CF1E2, 0x3DC87DD1, 0xAF07E544];
  
Blowfish.sBox3 = [
      0x6D15C286, 0xF89521E9, 0xF8CC6DB1, 0x98301160, 0xC7F2AF3B, 0x1CFB6ACF, 0x9CDD4420, 0xFA94237F, 
      0xA577E36A, 0x5023E9E5, 0xDDE9586E, 0x607C4213, 0x9E308CFD, 0x28A44E96, 0x724E12BA, 0xDEFB46DB,
      0xCA056D6B, 0x2874B76D, 0x9D3C8C3E, 0xE16C6F8E, 0x125FECCE, 0x92882BFB, 0x49AB5E50, 0xCEFCBA3D,
      0x77AF4B11, 0x0A1262D1, 0x20A30B89, 0x3DBFE017, 0x17DDCFD4, 0x84666271, 0xB9784AFB, 0x3EFB399A,
      0xDCAC8BA8, 0x2A4D0326, 0x2948DC71, 0xAF8DF960, 0x7DF39640, 0xCDEFB347, 0x20B0968E, 0x526814AE,
      0x54D77247, 0xD449FD5E, 0xCA33D49F, 0xFB1D62F0, 0xBE229CDD, 0x444A3B6D, 0xE3B90961, 0xA562B71D,
      0x0215589F, 0x70796307, 0x8B483614, 0x50BD48A2, 0x2D84D285, 0x5B063F81, 0x9B453B18, 0x779A5984,
      0xA9CC5C2C, 0xD009D429, 0x61223D7D, 0x24939708, 0xA9C1EDAC, 0x5118C8A3, 0x9ECB0F1F, 0x33604FBB,
      0xFFD65383, 0x7F3E7059, 0xF863093D, 0xD730A3A8, 0x6CE28FD7, 0x2B82A6B9, 0xEE36240E, 0x5FA4F99F,
      0xD0FF0873, 0xF989FFC3, 0x4546167F, 0xA7B5C435, 0x4DE3CFD4, 0x8926F61F, 0xB023D7BF, 0x4812D006,
      0x6CE4EF8F, 0xDBC0C50E, 0x7C259606, 0x8782BBAD, 0x916A2D76, 0xD31EA0F9, 0x9BF50299, 0xEB6AA2C0,
      0x2B035573, 0x4C5621D9, 0x30332C11, 0xA78A1D23, 0xCE1E0620, 0xF8E2D1F9, 0xE0CED680, 0xCFE5E23B,
      0x253ACB9F, 0xD0584813, 0xDC6A4694, 0xEDA07004, 0x5AF735F3, 0xC1166274, 0xEE83A9AE, 0x2A420F3D,
      0x42A9FB4D, 0x2B3C3D00, 0x02614151, 0xB9D449E6, 0xD87F1216, 0x4F792CC2, 0xC31ABC2A, 0xA203A3F2,
      0x52924E1D, 0x2FD64B56, 0x4FD2BE85, 0x11E5247F, 0x210CD634, 0xA263B9F6, 0xEFD2A821, 0x009091F5,
      0x19C77697, 0xBC5A96C5, 0xC39316DF, 0xB0329929, 0x6DE540DB, 0xAEBD2A9E, 0x7B2DBD38, 0x694A343C,
      0xB05B70CB, 0x1EEB074B, 0x235862B4, 0xA7E65967, 0x23D8C7B3, 0xB0D583A2, 0x613BBFB5, 0xD503D0B2,
      0x5CC8A37D, 0xE090B570, 0x321C1A59, 0xD1FDF898, 0xD302C3E1, 0xB00656BC, 0x9770987A, 0x159D1F4E,
      0x46239C8E, 0x5D6FADBD, 0xE83D33CB, 0xBFA18111, 0xDAE60055, 0xD841C373, 0xEAEE682A, 0x0CB2E3B1,
      0x4A2C4E60, 0xEA87EE24, 0x171C10B4, 0xD00219EC, 0x66A2913C, 0x78B5D353, 0xE7E46510, 0x693275C0,
      0xC30868E0, 0x0C7D9C5A, 0x28D41DB5, 0x29BC372A, 0x90DDF27A, 0x7118AB54, 0x2754306B, 0xDCA2EE55,
      0x4E8A65F9, 0xB637997A, 0xD17C08A8, 0xB2A48C7F, 0x74DAA09F, 0x7E0CA97F, 0x2E46A881, 0xFB9BBE66,
      0xFD28B222, 0x49E0E059, 0xBE054AE0, 0x6C627C33, 0xD5F6E9D6, 0x63ABFD1F, 0x2C38ADC3, 0x0D827685,
      0x7BB77729, 0x572CE480, 0x4D081490, 0x2A5F939D, 0xAC64BF0B, 0x4A1009AB, 0xD10BD292, 0x869B3755,
      0xEFAFBBF2, 0x35828E44, 0xE191C511, 0x5A3D060B, 0x35C2E2E1, 0x99BE122B, 0xEF93E1E4, 0x6E6551FD,
      0x0912831A, 0x2D688372, 0x03BC4F10, 0x2BEA7D42, 0xBC9AD8A3, 0xC1E8FA29, 0x1543C5D1, 0x572A8B40,
      0xFBCF19EF, 0x1E45FDD6, 0x9FEA58C9, 0xC301E3D3, 0x04589C22, 0xDD2C854A, 0x117DBF49, 0x812239A8,
      0x0817D019, 0x12219C1B, 0x9F8D4ADA, 0xD9A05C5B, 0xD378FFFB, 0x1FC3E2E0, 0x7D8BCF9B, 0x92705E9C,
      0x5B5B51D1, 0x833E5377, 0x31389C9F, 0x3D160D04, 0x21F9A1BB, 0xA1D7D797, 0xBD03E108, 0xAF13D3C2,
      0x3056EC50, 0xB90A7CDD, 0x4683524A, 0x1FB9151C, 0xF128ED86, 0xC4F9B9E3, 0xBD425784, 0xB27A31C6,
      0x9175F2F1, 0x82513590, 0x2A727EE4, 0x334D41F9, 0x657EA42F, 0xE0D3E2B0, 0xA39D0111, 0x564B68D9,
      0x651FC562, 0xCCAC4C4F, 0x0647632B, 0xB56817EC, 0xBA451301, 0xF6E393C1, 0xAFE3E016, 0x927F7166];
