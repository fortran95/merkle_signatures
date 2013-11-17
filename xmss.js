var crypto = require('crypto');
function hash256(data){
    var algorithm = 'sha256', encoding = 'binary';
    var digestor = new crypto.createHash(algorithm);
    digestor.update(data, encoding);
    var buffer = digestor.digest();
    return buffer.toString('binary');
};

function xmss(){
    
    var n = 256,    // the security parameter
        w = 2,      // w>1, the Winternitz parameter
        m = 256,    // the message length in bits

        H = 80,     // the tree height, 
                    // XMSS allows to make 2**H signatures using one key pair
        x = hash256('XMSS');
                    // used to construct one-time verification keys

    // a function family
    function f_K(string_of_n){
    };

    function h_K(string_of_2n){
        // a hash function, choosen randomly with the uniform distribution
        // from the family H.
    };

    /* ABOVE PARAMETERS ARE PUBLICLY KNOWN. */

};

var x = xmss();
