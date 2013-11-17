var crypto = require('crypto'),
    buffer = require('buffer');
function hash_n(data){
    var algorithm = 'sha256', encoding = 'binary';
    var digestor = new crypto.createHash(algorithm);
    digestor.update(data, encoding);
    var buffer = digestor.digest();
    return buffer;
};

function rebase_string(string, w_bits){
    var binstr = '';
    var buf = new buffer.Buffer(string, 'ascii');
    string = buf.toString('hex');
    for(var i=0; i<string.length; i++){
        var b = parseInt(string.substr(i,1), 16).toString(2);
        binstr += '0000'.substr(0, 4-b.length) + b;
    };

    var pad_zero_count = binstr.length % w_bits;
    if(pad_zero_count > 0)
        binstr = 
            '000000000000000000000'.substr(0, w_bits - pad_zero_count)
            + binstr
        ;

    var result = [];
    while(binstr != ''){
        var fetch = binstr.substr(0, w_bits);
        binstr = binstr.substr(w_bits);
        result.push(parseInt(fetch, 2));
    };
    console.log(result.join('|'));
    return result;
};

function xmss(){
    /* 
     * In this sample, the Winternitz parameter is implemented to be
     * exponents of 2. This makes sense, in the author's opinion, because
     * the Winternitz method is trying to reduce the count of total hashes
     * in a signature by representing the message being signed with a larger 
     * base. And it is easier, to break up the input and use 1 and 0s to
     * divide.
     */
    var w_bits = 4; // currently <= 5 is OK. larger not implemented.
    
    var n = 256,    // the security parameter
        w = Math.pow(2, w_bits), 
                    // w>1, the Winternitz parameter
        m = 256,    // the message length in bits

        H = 80,     // the tree height, 
                    // XMSS allows to make 2**H signatures using one key pair
        x = hash_n('XMSS');
                    // used to construct one-time verification keys

    // a function family
    function f_K(K, e, string_of_n){
        if(string_of_n.length * 8 != n) throw Error();
        if(K.length * 8 != n) throw Error();

        if(0 == e)
            return K;
        else{
            var K_ = f_K(K, e-1, string_of_n);
            return hash_n(K_ + '||' + string_of_n);
        };

    };

    function h_K(string_of_2n){
        // a hash function, choosen randomly with the uniform distribution
        // from the family H.
        assert(string_of_2n.length * 4 == n);

    };

    /* ABOVE PARAMETERS ARE PUBLICLY KNOWN. */

    
    var Winternitz_OTS = function(){
        var self = this;

        var l_1 = Math.ceil(m / Math.log(w) * Math.log(2)),
            l_2 = Math.floor(Math.log(l_1 * (w - 1)) / Math.log(w)) + 1,
            l = l_1 + l_2;

        var signature_key = false;
        var verification_key = false;

        this.generate_signature_key = function(){
            /*
             * The secret signature key of W-OTS consists of l n-bit strings
             * sk_i , 1 <= i <= l chosen uniformly at random.
             */
            
            var result = [];
            for(var i=1; i<=l; i++){
                result.push(crypto.randomBytes(n / 8));
            };
            return result;
        };

        this.set_signature_key = function(sk_i){
            if(sk_i.length != l) throw Error();
            for(var i=1; i<=l; i++){
                if(n / 8 != sk_i[i-1].length) throw Error();
            };
            signature_key = sk_i;
        };

        this.set_verification_key = function(pk_i){
            assert(pk_i.length == l);
            for(var i=1; i<=l; i++){
                assert(n / 8 == pk_i[i-1].length);
            };
            verification_key = pk_i;
        };

        this.get_verification_key = function(){
            if(verification_key != false) return verification_key;
            /*
             * The public verification key is computed as
             *  pk = (pk_1, ..., pk_l)=(f_sk_1^w-1(x), ..., f_sk_l^(w-1)(x)),
             * with f^(w-1) as defined above.
             */
            if(false == signature_key)
                throw Error();

            var pk = [];
            for(i=1; i<=l; i++){
                var pk_i = f_K(signature_key[i-1], w-1, x);
                pk.push(pk_i);
            };

            return pk;
        };

        function b_l(message){
            var M = [], b = [], C = 0;
            // W-OTS signs messages of binary length m.
            if(m != message.length * 8) throw Error();

            // They are processed in base w representation.
            M = rebase_string(message, w_bits);
            console.log(l_1, l_2, M.length, C);
            if(l_1 != M.length) throw Error();
            // The checksum ...
            for(var i=1; i<=l_1; i++){
                C += w - 1 - M[i-1];
            };

            // in base w representation... 
            C = C.toString(w).split('');

            // is appended to M.
            b = M.slice(0, M.length);
            for(var i in C)
                b.push(parseInt(C[i], w));
            
            // It is of length l_2
            if(l_2 != C.length) throw Error();

            // The result is (b_1, ..., b_l)

            if(l != b.length) throw Error();

            return b;            
        };

        this.sign = function(message){
            var b = b_l(message);
            
            // The signature of M is
            var sigma = [];
            for(var i=1; i<=l; i++){
                var sigma_i = f_K(signature_key[i-1], b[i-1], x);
                sigma.push(sigma_i);
            };
            return [sigma, x];
        };

        this.verify = function(message, signature){
            // It is verified by constructing (b_1, ..., b_l)...
            var b = b_l(message);

            var pk = self.get_verification_key();

            // and checking
            for(var i=1; i<=l; i++){
                if(
                    pk[i-1] !=
                    f_K(signature[0][i-1], w-1-b[i-1], signature[1])
                ){
                    console.log('failed @ ' + i);
                    return false;
                };
            };

            return true;
        };

        return this;
    };

    this.winternitz = Winternitz_OTS;

    return this;
};

var x = new xmss();

var test = new x.winternitz();
var secretkey = test.generate_signature_key();
test.set_signature_key(secretkey);
var publickey = test.get_verification_key();

var signtext = hash_n('abc');

var signature = test.sign(hash_n('abc'));
var verify = test.verify(signtext, signature);
console.log(verify);
