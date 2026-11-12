#include <metal_stdlib>
using namespace metal;
#include "sha512-constants.metal"

struct U { uint v[8]; };
constant uint PRIME[8]={0xfffffc2f,0xfffffffe,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff,0xffffffff};
constant uint ORDER[8]={0xd0364141,0xbfd25e8c,0xaf48a03b,0xbaaedce6,0xfffffffe,0xffffffff,0xffffffff,0xffffffff};
U zero(){U a;for(uint i=0;i<8;i++)a.v[i]=0;return a;}
U one(){U a=zero();a.v[0]=1;return a;}
bool iszero(U a){uint x=0;for(uint i=0;i<8;i++)x|=a.v[i];return x==0;}
bool ge(U a,constant uint* b){for(int i=7;i>=0;i--){if(a.v[i]!=b[i])return a.v[i]>b[i];}return true;}
U submodulus(U a,constant uint* b){ulong borrow=0;for(uint i=0;i<8;i++){ulong t=ulong(a.v[i])-b[i]-borrow;a.v[i]=uint(t);borrow=t>>63;}return a;}
void addat(thread uint* t,uint at,ulong value){while(value!=0 && at<16){value+=t[at];t[at++]=uint(value);value>>=32;}}
U reduce(thread uint* t){
    for(uint pass=0;pass<3;pass++)for(int i=15;i>=8;i--){uint h=t[i];t[i]=0;addat(t,uint(i-8),ulong(h)*977);addat(t,uint(i-7),h);}
    U r;for(uint i=0;i<8;i++)r.v[i]=t[i];if(ge(r,PRIME))r=submodulus(r,PRIME);return r;
}
U mul(U a,U b){uint t[16]={0};for(uint i=0;i<8;i++){ulong carry=0;for(uint j=0;j<8;j++){ulong x=ulong(a.v[i])*b.v[j]+t[i+j]+carry;t[i+j]=uint(x);carry=x>>32;}t[i+8]=uint(carry);}return reduce(t);}
U sq(U a){return mul(a,a);}
U add(U a,U b){uint t[16]={0};ulong carry=0;for(uint i=0;i<8;i++){ulong x=ulong(a.v[i])+b.v[i]+carry;t[i]=uint(x);carry=x>>32;}t[8]=uint(carry);return reduce(t);}
U sub(U a,U b){U r;ulong borrow=0;for(uint i=0;i<8;i++){ulong t=ulong(a.v[i])-b.v[i]-borrow;r.v[i]=uint(t);borrow=t>>63;}if(borrow){ulong c=0;for(uint i=0;i<8;i++){ulong t=ulong(r.v[i])+PRIME[i]+c;r.v[i]=uint(t);c=t>>32;}}return r;}
U twice(U a){return add(a,a);}
U squares(U a,uint n){for(uint i=0;i<n;i++)a=sq(a);return a;}
// Addition chain for a^(p-2): 255 squares and 15 multiplies.
U inverse(U a){
    U x2=mul(sq(a),a),x3=mul(sq(x2),a);
    U x6=mul(squares(x3,3),x3),x9=mul(squares(x6,3),x3);
    U x11=mul(squares(x9,2),x2),x22=mul(squares(x11,11),x11);
    U x44=mul(squares(x22,22),x22),x88=mul(squares(x44,44),x44);
    U x176=mul(squares(x88,88),x88),x220=mul(squares(x176,44),x44);
    U x223=mul(squares(x220,3),x3),t=mul(squares(x223,23),x22);
    t=mul(squares(t,5),a);t=mul(squares(t,3),x2);return mul(squares(t,2),a);
}
struct Point {U x;U y;U z;};
Point dbl(Point p){
    U a=sq(p.x), b=sq(p.y), c=sq(b), d=twice(sub(sub(sq(add(p.x,b)),a),c));
    U e=add(twice(a),a),f=sq(e);Point r;r.x=sub(f,twice(d));r.y=sub(mul(e,sub(d,r.x)),twice(twice(twice(c))));r.z=twice(mul(p.y,p.z));return r;
}
Point mixed(Point p,U x,U y){
    if(iszero(p.z)){p.x=x;p.y=y;p.z=one();return p;}
    U z2=sq(p.z),u=mul(x,z2),s=mul(y,mul(p.z,z2)),h=sub(u,p.x),r=sub(s,p.y);
    if(iszero(h)){if(iszero(r))return dbl(p);p.z=zero();return p;}
    U hh=sq(h),hhh=mul(h,hh),v=mul(p.x,hh);Point q;q.x=sub(sub(sq(r),hhh),twice(v));q.y=sub(mul(r,sub(v,q.x)),mul(p.y,hhh));q.z=mul(p.z,h);return q;
}
U frombytes(thread const uchar* b){U a;for(uint i=0;i<8;i++){uint at=28-4*i;a.v[i]=(uint(b[at])<<24)|(uint(b[at+1])<<16)|(uint(b[at+2])<<8)|b[at+3];}return a;}
void tobytes(U a,thread uchar* b){for(uint i=0;i<8;i++)for(uint j=0;j<4;j++)b[31-i*4-j]=uchar(a.v[i]>>(8*j));}
void pubkey(U scalar,device const uint* table,thread uchar* out,uint window_bits){
    Point p;p.z=zero();p.x=zero();p.y=zero();
    uint entries=(1u<<window_bits)-1;
    for(uint w=0;w<256/window_bits;w++){uint bit=w*window_bits;uint digit=(scalar.v[bit/32]>>(bit%32))&entries;if(digit){uint off=(w*entries+digit-1)*16;U x,y;for(uint j=0;j<8;j++){x.v[j]=table[off+j];y.v[j]=table[off+8+j];}p=mixed(p,x,y);}}
    U zi=inverse(p.z),z2=sq(zi),x=mul(p.x,z2),y=mul(p.y,mul(z2,zi));out[0]=uchar(2|(y.v[0]&1));tobytes(x,out+1);
}
U scalaradd(U a,U b){U r;ulong c=0;for(uint i=0;i<8;i++){ulong t=ulong(a.v[i])+b.v[i]+c;r.v[i]=uint(t);c=t>>32;}if(c||ge(r,ORDER))r=submodulus(r,ORDER);return r;}

ulong rotr(ulong x,uint n){return(x>>n)|(x<<(64-n));}
void shainit(thread ulong* h){h[0]=0x6a09e667f3bcc908UL;h[1]=0xbb67ae8584caa73bUL;h[2]=0x3c6ef372fe94f82bUL;h[3]=0xa54ff53a5f1d36f1UL;h[4]=0x510e527fade682d1UL;h[5]=0x9b05688c2b3e6c1fUL;h[6]=0x1f83d9abfb41bd6bUL;h[7]=0x5be0cd19137e2179UL;}
void shablock(thread ulong* h,thread const uchar* bytes){
    ulong w[16];for(uint i=0;i<16;i++){w[i]=0;for(uint j=0;j<8;j++)w[i]=(w[i]<<8)|bytes[i*8+j];}
    ulong a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],v=h[7];
    for(uint i=0;i<80;i++){
        if(i>=16){ulong x=w[(i+1)&15],y=w[(i+14)&15];w[i&15]+=(rotr(x,1)^rotr(x,8)^(x>>7))+w[(i+9)&15]+(rotr(y,19)^rotr(y,61)^(y>>6));}
        ulong t=v+(rotr(e,14)^rotr(e,18)^rotr(e,41))+((e&f)^((~e)&g))+SHA_K[i]+w[i&15];
        ulong u=(rotr(a,28)^rotr(a,34)^rotr(a,39))+((a&b)^(a&c)^(b&c));v=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+u;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=v;
}
void shaout(thread const ulong* h,thread uchar* out){for(uint i=0;i<8;i++)for(uint j=0;j<8;j++)out[i*8+j]=uchar(h[i]>>(56-8*j));}
void hmac512(thread const uchar* key,uint keylen,thread const uchar* msg,uint len,thread uchar* out){
    uchar block[128],inner[64];ulong h[8];
    for(uint i=0;i<128;i++)block[i]=(i<keylen?key[i]:uchar(0))^uchar(0x36);
    shainit(h);shablock(h,block);for(uint i=0;i<128;i++)block[i]=0;for(uint i=0;i<len;i++)block[i]=msg[i];block[len]=0x80;uint bits=(128+len)*8;block[126]=uchar(bits>>8);block[127]=uchar(bits);shablock(h,block);shaout(h,inner);
    for(uint i=0;i<128;i++)block[i]=(i<keylen?key[i]:uchar(0))^uchar(0x5c);
    shainit(h);shablock(h,block);for(uint i=0;i<128;i++)block[i]=0;for(uint i=0;i<64;i++)block[i]=inner[i];block[64]=0x80;block[126]=6;shablock(h,block);shaout(h,out);
}

kernel void search(device const uchar* entropy [[buffer(0)]],device uchar* output [[buffer(1)]],constant uint4& params [[buffer(2)]],device const uchar* prefix [[buffer(3)]],device const uint* table [[buffer(4)]],device atomic_uint* winner [[buffer(5)]],constant uint& window_bits [[buffer(6)]],uint tid [[thread_position_in_grid]]){
    if(tid>=params.x)return;
    uchar seed[16],key[32],chain[32],digest[64],data[37],pk[33];
    for(uint i=0;i<16;i++)seed[i]=entropy[tid*16+i];
    uchar masterkey[12]={'B','i','t','c','o','i','n',' ','s','e','e','d'};hmac512(masterkey,12,seed,16,digest);
    U scalar=frombytes(digest);bool valid=!iszero(scalar)&&!ge(scalar,ORDER);
    for(uint i=0;i<32;i++){key[i]=digest[i];chain[i]=digest[32+i];}
    if(params.w)for(uint i=0;i<64;i++)output[tid*418+1+i]=digest[i];
    uint indices[5]={0x800003f9,0x80000000|params.y,0x80000006,0,0};
    for(uint step=0;step<5&&valid;step++){
        if(step<3){data[0]=0;for(uint i=0;i<32;i++)data[i+1]=key[i];}else{pubkey(scalar,table,pk,window_bits);for(uint i=0;i<33;i++)data[i]=pk[i];}
        uint child=indices[step];for(uint j=0;j<4;j++)data[33+j]=uchar(child>>(24-j*8));
        hmac512(chain,32,data,37,digest);U tweak=frombytes(digest);if(ge(tweak,ORDER)){valid=false;break;}scalar=scalaradd(scalar,tweak);if(iszero(scalar)){valid=false;break;}
        tobytes(scalar,key);for(uint i=0;i<32;i++)chain[i]=digest[32+i];
        if(params.w)for(uint i=0;i<32;i++){output[tid*418+1+(step+1)*64+i]=key[i];output[tid*418+33+(step+1)*64+i]=chain[i];}
    }
    if(valid)pubkey(scalar,table,pk,window_bits);
    if(params.w){output[tid*418]=valid?1:0;if(valid)for(uint i=0;i<33;i++)output[tid*418+385+i]=pk[i];return;}
    bool matches=valid&&params.z>0;for(uint i=0;i<params.z&&matches;i++)matches=pk[i]==prefix[i];
    if(matches){uint expected=0xffffffff;while(expected==0xffffffff){if(atomic_compare_exchange_weak_explicit(winner,&expected,tid,memory_order_relaxed,memory_order_relaxed)){for(uint i=0;i<33;i++)output[i]=pk[i];break;}}}
}
