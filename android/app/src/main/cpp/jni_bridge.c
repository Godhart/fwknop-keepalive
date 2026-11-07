#include <jni.h>
#include <stdlib.h>
#include "packet.h"
JNIEXPORT jstring JNICALL Java_org_example_spakeepalive_NativeSpa_encode(
    JNIEnv *env,jclass cls,jstring message,jstring username,jint timeout,jbyteArray key,jbyteArray hmac) {
    (void)cls;
    if(!message || !username || !key || !hmac) return NULL;
    const char *msg=(*env)->GetStringUTFChars(env,message,NULL);
    if(!msg) return NULL;
    const char *user=(*env)->GetStringUTFChars(env,username,NULL);
    if(!user){(*env)->ReleaseStringUTFChars(env,message,msg);return NULL;}
    jsize kl=(*env)->GetArrayLength(env,key),hl=(*env)->GetArrayLength(env,hmac);
    unsigned char k[32]={0},h[64]={0};
    char *packet=NULL; int rc=-1;
    if(kl>=16 && kl<=32 && hl>=32 && hl<=64) {
        (*env)->GetByteArrayRegion(env,key,0,kl,(jbyte*)k);
        (*env)->GetByteArrayRegion(env,hmac,0,hl,(jbyte*)h);
        if(!(*env)->ExceptionCheck(env)) rc=spa_packet(msg,user,timeout,k,kl,h,hl,&packet);
    }
    volatile unsigned char *v=k; for(int i=0;i<32;i++) v[i]=0;
    v=h; for(int i=0;i<64;i++) v[i]=0;
    (*env)->ReleaseStringUTFChars(env,message,msg);
    (*env)->ReleaseStringUTFChars(env,username,user);
    if((*env)->ExceptionCheck(env)) {free(packet); return NULL;}
    if(rc!=0 || !packet) {
        jclass error=(*env)->FindClass(env,"java/lang/IllegalStateException");
        if(error) (*env)->ThrowNew(env,error,"libfko failed to encode SPA");
        free(packet); return NULL;
    }
    jstring result=(*env)->NewStringUTF(env,packet);free(packet);return result;
}
