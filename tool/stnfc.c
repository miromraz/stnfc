/* stnfc.c -- minimal NCI-over-I2C bringup harness for the ST21NFC CLF
 * on the Google Pixel 4a (sunfish).  Phase-2 userspace test tool.
 *
 *   Bus  : /dev/i2c-2   (Geni-I2C = &i2c2 = i2c@888000)   slave 0x08
 *   GPIO : reset/VEN = TLMM 67      IRQ/host-int = TLMM 37
 *
 * Build (workstation):
 *   aarch64-linux-gnu-gcc -O2 -static -Wall -o stnfc stnfc.c
 *
 * Run on the phone as root (doas).  Subcommands:
 *   info            list gpiochips, identify TLMM, show config
 *   reset           pulse the reset/VEN line only, report IRQ level
 *   nci             reset + CORE_RESET + CORE_INIT, print chip identity
 *   poll            reset + NCI init + RF discovery, report detected tag
 *   read [blk cnt]  poll + MIFARE Classic auth (key A FF*6) + block read
 *   write blk [hex] MIFARE Classic auth + write a data block + verify
 *   dump            full MIFARE Classic 1K dump (16 sectors * 4 blocks, key A FF*6)
 *   keys            MIFARE Classic key-A dictionary attack against the
 *                   current tag using a built-in list of common defaults
 *   apdu HH HH ...  detect an ISO-DEP card and send a single APDU, print
 *                   response data + SW1 SW2 with a short status decode
 *                   (e.g. apdu 00 A4 04 00 0E 31 50 41 59 2E 53 59 53 2E
 *                    44 44 46 30 31 00   to read an EMV bank card's PSE)
 *   ndef-read       detect tag, read & parse the NDEF message
 *                   (Type 2 / NTAG / Ultralight and Type 4 / ISO-DEP)
 *   ndef-write <url-or-text>
 *                   detect a Type 2 tag (NTAG/Ultralight) and write the
 *                   given URL or text as an NDEF record (with verify)
 *   emulate-ndef [url-or-text]
 *                   reset + NCI init + listen-mode discovery + Type 4 NDEF
 *                   tag emulation (phone shows up as an NFC tag containing
 *                   the given URL or text; default is the project repo URL)
 *   emulate-wifi <SSID> [password] [OPEN]
 *                   emulate an NFC Wi-Fi-config tag (WFA WSC Credential
 *                   in a Type 4 NDEF MIME record). Tap a receiver phone
 *                   to auto-join the named network.
 *   emulate-vcard <name> [phone] [email]
 *                   emulate a vCard 3.0 NDEF tag (MIME text/vcard). The
 *                   receiver phone offers to add a new contact.
 *   emulate-apdu <conf>
 *                   reset + NCI init + listen-mode + programmable HCE.
 *                   Lines in <conf> map APDU patterns to responses:
 *                     HEX_PATTERN [*] : HEX_RESPONSE
 *                     '*' alone matches any APDU; trailing '*' = prefix.
 *   clone <out>     scan whatever tag is on the phone, capture its data,
 *                   and write an `emulate-apdu`-ready config (NDEF tags)
 *                   or a hex dump (MIFARE Classic, which the chip cannot
 *                   listen-emulate). Replay with `emulate-apdu <out>`.
 *   mfc-copy [--write-trailers] <dump-file>
 *                   read a MIFARE Classic 1K dump (from `clone`) and
 *                   write it to the tag currently on the phone. Block 0
 *                   (UID/manufacturer) is always skipped (read-only on
 *                   standard MIFARE Classic). Sector trailers are skipped
 *                   by default -- they hold keys+access bits and writing
 *                   bad values bricks the sector.
 *   drain           reset + just read whatever the chip emits
 *   raw HH HH ...   reset + send one NCI packet, read replies
 *
 * Flags (before the subcommand):
 *   --bus PATH   --addr 0xNN   --chip N   --rst N   --irq N
 *   --inv-reset  (reset line is active-low: low = chip ON)
 *   --inv-irq    (IRQ asserted low)
 *   --no-reset   (skip the reset pulse)
 *   --timeout MS (per-read IRQ wait, default 1000)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/ioctl.h>
#include <linux/gpio.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>

/* ---- config (overridable via flags) ------------------------------------ */
static const char *g_bus   = "/dev/i2c-2";
static int  g_addr         = 0x08;
static int  g_chip         = -1;     /* TLMM gpiochip index, -1 = auto      */
static int  g_rst          = 67;     /* reset/VEN line offset on TLMM       */
static int  g_irq          = 37;     /* IRQ/host-int line offset on TLMM    */
static int  g_inv_reset    = 0;      /* 0: high = chip ON (active-high)     */
static int  g_inv_irq      = 0;      /* 0: high = data ready                */
static int  g_no_reset     = 0;
static int  g_timeout      = 1000;   /* ms to wait for IRQ per read         */
static uint8_t g_la_nfcid1[10];      /* listen-mode NFCID1 (UID) spoof      */
static int  g_la_nfcid1_len = 0;     /* 0 = use chip default; 4/7/10 = spoof */

/* ---- small helpers ----------------------------------------------------- */
static void msleep(int ms){ struct timespec t={ms/1000,(long)(ms%1000)*1000000L}; nanosleep(&t,0); }

static void hexdump(const char *pfx, const uint8_t *b, int n){
    printf("%s", pfx);
    for(int i=0;i<n;i++) printf(" %02x", b[i]);
    printf("\n");
}

/* ---- GPIO (chardev v2 uABI) -------------------------------------------- */
static int gpio_find_tlmm(void){
    int best=-1; uint32_t bestlines=0;
    for(int i=0;i<16;i++){
        char p[32]; snprintf(p,sizeof p,"/dev/gpiochip%d",i);
        int fd=open(p,O_RDONLY|O_CLOEXEC);
        if(fd<0) continue;
        struct gpiochip_info ci; memset(&ci,0,sizeof ci);
        if(ioctl(fd,GPIO_GET_CHIPINFO_IOCTL,&ci)==0 && ci.lines>bestlines){
            bestlines=ci.lines; best=i;
        }
        close(fd);
    }
    return best;   /* TLMM has by far the most lines on this SoC */
}

static void gpio_list(void){
    for(int i=0;i<16;i++){
        char p[32]; snprintf(p,sizeof p,"/dev/gpiochip%d",i);
        int fd=open(p,O_RDONLY|O_CLOEXEC);
        if(fd<0) continue;
        struct gpiochip_info ci; memset(&ci,0,sizeof ci);
        if(ioctl(fd,GPIO_GET_CHIPINFO_IOCTL,&ci)==0)
            printf("  gpiochip%-2d  name=%-16s label=%-20s lines=%u\n",
                   i, ci.name, ci.label, ci.lines);
        close(fd);
    }
}

static int gpio_request(int chipidx, unsigned off, int output, int initval){
    char p[32]; snprintf(p,sizeof p,"/dev/gpiochip%d",chipidx);
    int cfd=open(p,O_RDONLY|O_CLOEXEC);
    if(cfd<0){ perror(p); return -1; }
    struct gpio_v2_line_request req; memset(&req,0,sizeof req);
    req.offsets[0]=off; req.num_lines=1;
    snprintf(req.consumer,sizeof req.consumer,"stnfc");
    req.config.flags = output ? GPIO_V2_LINE_FLAG_OUTPUT
                              : GPIO_V2_LINE_FLAG_INPUT;
    if(output){
        req.config.num_attrs=1;
        req.config.attrs[0].attr.id=GPIO_V2_LINE_ATTR_ID_OUTPUT_VALUES;
        req.config.attrs[0].attr.values=initval?1:0;
        req.config.attrs[0].mask=1;
    }
    int r=ioctl(cfd,GPIO_V2_GET_LINE_IOCTL,&req);
    close(cfd);
    if(r<0){ fprintf(stderr,"GPIO_V2_GET_LINE off=%u: %s\n",off,strerror(errno)); return -1; }
    return req.fd;
}

static int gpio_set(int fd,int val){
    struct gpio_v2_line_values v; v.bits=val?1:0; v.mask=1;
    return ioctl(fd,GPIO_V2_LINE_SET_VALUES_IOCTL,&v);
}
static int gpio_get(int fd){
    struct gpio_v2_line_values v; v.bits=0; v.mask=1;
    if(ioctl(fd,GPIO_V2_LINE_GET_VALUES_IOCTL,&v)<0) return -1;
    return (int)(v.bits&1);
}

/* ---- chip reset -------------------------------------------------------- */
/* reset/VEN: active-high -> physical high = chip powered & running.
 * Double-pulse mirrors the downstream ST21NFC_PULSE_RESET (exit quick-boot). */
static void chip_reset(int rstfd){
    int on  = g_inv_reset ? 0 : 1;
    int off = !on;
    gpio_set(rstfd,off); msleep(20);
    gpio_set(rstfd,on);  msleep(10);
    gpio_set(rstfd,off); msleep(20);
    gpio_set(rstfd,on);  msleep(20);   /* chip now booting into NCI mode   */
}

/* ---- I2C / NCI --------------------------------------------------------- */
static int i2c_open(void){
    int fd=open(g_bus,O_RDWR);
    if(fd<0){ perror(g_bus); return -1; }
    if(ioctl(fd,I2C_SLAVE,g_addr)<0){ perror("I2C_SLAVE"); close(fd); return -1; }
    return fd;
}

static int nci_write(int i2cfd,const uint8_t *buf,int len){
    int n=-1;
    for(int tries=0;tries<12;tries++){              /* chip may still be booting */
        n=write(i2cfd,buf,len);
        if(n==len) return 0;
        if(errno!=ENXIO) break;                     /* only retry the not-ready NACK */
        msleep(20);
    }
    fprintf(stderr,"  i2c write FAILED (%d/%d): %s%s\n",n,len,strerror(errno),
            errno==ENXIO?"  <- chip not ACKing after retries (wrong addr / held in reset?)":"");
    return -1;
}

static int wait_irq(int irqfd,int timeout_ms){
    int want = g_inv_irq ? 0 : 1;
    for(int i=0;i<timeout_ms;i++){
        int v=gpio_get(irqfd);
        if(v<0) return -1;
        if(v==want) return 0;
        msleep(1);
    }
    return -2;   /* timeout: no packet */
}

/* read one NCI packet: 3-byte header then payload. ret total len, <0 err. */
static int nci_read(int i2cfd,int irqfd,uint8_t *buf,int timeout_ms){
    int w=wait_irq(irqfd,timeout_ms);
    if(w==-2) return -2;
    if(w<0)   return -1;
    int n=read(i2cfd,buf,3);
    if(n!=3){ fprintf(stderr,"  i2c header read %d/3: %s\n",n,strerror(errno)); return -1; }
    int plen=buf[2];
    if(plen>0){
        int m=read(i2cfd,buf+3,plen);
        if(m!=plen){ fprintf(stderr,"  i2c payload read %d/%d: %s\n",m,plen,strerror(errno)); return -1; }
    }
    return 3+plen;
}

static const char* mt_name(uint8_t b0){
    switch((b0>>5)&7){
        case 0:return "DATA"; case 1:return "CMD";
        case 2:return "RSP";  case 3:return "NTF";
        default:return "?";
    }
}
static const char* proto_name(int p){
    switch(p){
        case 0x01:return "T1T";      case 0x02:return "T2T";
        case 0x03:return "T3T";      case 0x04:return "ISO-DEP";
        case 0x05:return "NFC-DEP";  case 0x06:return "T5T/ISO15693";
        case 0x80:case 0x90:return "MIFARE Classic"; default:return "?";
    }
}
static const char* tech_name(int t){
    switch(t){
        case 0x00:return "NFC-A passive poll"; case 0x01:return "NFC-B passive poll";
        case 0x02:return "NFC-F passive poll"; case 0x03:return "NFC-A active poll";
        case 0x05:return "NFC-F active poll";  case 0x06:return "NFC-V passive poll";
        case 0x80:return "NFC-A passive listen"; case 0x81:return "NFC-B passive listen";
        case 0x82:return "NFC-F passive listen"; case 0x83:return "NFC-A active listen";
        case 0x85:return "NFC-F active listen";
        default:return "?";
    }
}
static const char* sak_name(int s){
    switch(s){
        case 0x00:return "MIFARE Ultralight / NTAG (NFC Forum Type 2)";
        case 0x08:return "MIFARE Classic 1K";
        case 0x09:return "MIFARE Mini";
        case 0x18:return "MIFARE Classic 4K";
        case 0x10:case 0x11:return "MIFARE Plus";
        case 0x20:return "ISO 14443-4 (DESFire / JCOP / smartcard)";
        case 0x28:return "ISO 14443-4 + MIFARE (combi)";
        case 0x40:return "NFC-DEP (P2P target)";
        default:return "unknown";
    }
}

/* CORE_RESET_NTF (60 00): decode chip identity */
static void print_identity(const uint8_t *b,int n){
    if(n<3+4) return;
    const uint8_t *p=b+3;
    int nciver=p[2], mfr=p[3];
    printf("  >> chip identity: NCI %d.%d, Manufacturer 0x%02x (%s)\n",
           nciver>>4, nciver&0x0F, mfr,
           mfr==0x02?"STMicroelectronics":mfr==0x04?"NXP":"?");
}

/* a detected tag, parsed from NFC-A technology-specific parameters */
static int g_tag_found=0;
static uint8_t g_uid[10]; static int g_uidlen=0; static int g_sak=-1;
static int g_rf_proto=0;
static void report_tag(int proto,int techmode,const uint8_t *pp,int n){
    g_tag_found=1;
    g_rf_proto=proto;
    printf("\n*** TAG DETECTED ***\n");
    printf("  RF protocol  : 0x%02x (%s)\n",proto,proto_name(proto));
    printf("  Technology   : 0x%02x (%s)\n",techmode,tech_name(techmode));
    if((techmode==0x00||techmode==0x03) && n>=3){          /* NFC-A layout */
        int uidlen=pp[2];
        if(3+uidlen+1<=n){
            g_uidlen = uidlen<=10?uidlen:10;
            memcpy(g_uid,pp+3,g_uidlen);
            printf("  ATQA(SENS_RES): %02x %02x\n",pp[0],pp[1]);
            printf("  UID (NFCID1) :");
            for(int i=0;i<uidlen;i++) printf(" %02x",pp[3+i]);
            printf("   (%d bytes)\n",uidlen);
            int selreslen=pp[3+uidlen];
            if(selreslen>=1 && 3+uidlen+2<=n){
                g_sak=pp[3+uidlen+1];
                printf("  SAK (SEL_RES): 0x%02x  -> %s\n",g_sak,sak_name(g_sak));
            }
        }
    } else {
        printf("  tech params  :");
        for(int i=0;i<n;i++) printf(" %02x",pp[i]);
        printf("\n");
    }
    printf("\n");
}

static void nci_decode(const uint8_t *b,int n){
    if(n<3){ hexdump("  short:",b,n); return; }
    printf("  %-3s gid=%X oid=%02x len=%d :",mt_name(b[0]),b[0]&0x0F,b[1],b[2]);
    for(int i=3;i<n;i++) printf(" %02x",b[i]);
    printf("\n");
    if(b[0]==0x60 && b[1]==0x00) print_identity(b,n);          /* CORE_RESET_NTF */
    if(b[0]==0x61 && b[1]==0x05 && n>=3+7){                     /* RF_INTF_ACTIVATED_NTF */
        int proto=b[3+2], tm=b[3+3], np=b[3+6];
        if(3+7+np<=n) report_tag(proto,tm,b+3+7,np);
    }
    if(b[0]==0x61 && b[1]==0x03 && n>=3+4){                     /* RF_DISCOVER_NTF */
        int proto=b[3+1], tm=b[3+2], np=b[3+3];
        if(3+4+np<=n) report_tag(proto,tm,b+3+4,np);
    }
}

/* read & decode replies until the chip goes quiet */
static int nci_drain(int i2cfd,int irqfd,int first_to,int idle_to){
    uint8_t buf[300]; int got=0,to=first_to;
    for(;;){
        int n=nci_read(i2cfd,irqfd,buf,to);
        if(n==-2) break;            /* timed out -> quiet */
        if(n<0)   return got?got:-1;
        nci_decode(buf,n);
        got++; to=idle_to;
    }
    return got;
}

/* ---- subcommands ------------------------------------------------------- */
static int do_info(void){
    printf("gpiochips:\n"); gpio_list();
    int t = g_chip>=0 ? g_chip : gpio_find_tlmm();
    printf("TLMM gpiochip : %d %s\n", t, g_chip>=0?"(forced)":"(auto: most lines)");
    printf("i2c bus       : %s   slave 0x%02x\n", g_bus, g_addr);
    printf("reset/VEN line: %d   IRQ line: %d\n", g_rst, g_irq);
    return 0;
}

static int do_reset(void){
    int t = g_chip>=0 ? g_chip : gpio_find_tlmm();
    if(t<0){ fprintf(stderr,"no TLMM gpiochip\n"); return 1; }
    int rst=gpio_request(t,g_rst,1,g_inv_reset?0:1);
    int irq=gpio_request(t,g_irq,0,0);
    if(rst<0||irq<0) return 1;
    printf("IRQ before reset : %d\n",gpio_get(irq));
    chip_reset(rst);
    printf("reset pulse done (chip %d line %d)\n",t,g_rst);
    msleep(50);
    printf("IRQ after  reset : %d  %s\n",gpio_get(irq),
           gpio_get(irq)==(g_inv_irq?0:1) ? "(asserted -> chip has data)" : "");
    return 0;
}

static int prep(int *i2cfd,int *irqfd){          /* shared bring-to-life path */
    int t = g_chip>=0 ? g_chip : gpio_find_tlmm();
    if(t<0){ fprintf(stderr,"no TLMM gpiochip\n"); return -1; }
    int rst=gpio_request(t,g_rst,1,g_inv_reset?0:1);
    int irq=gpio_request(t,g_irq,0,0);
    if(rst<0||irq<0) return -1;
    if(!g_no_reset){
        chip_reset(rst);
        if(wait_irq(irq,1500)==0) printf("chip ready (post-reset IRQ asserted)\n");
        else                      printf("WARNING: no post-reset IRQ within 1500 ms\n");
    }
    int fd=i2c_open();
    if(fd<0) return -1;
    *i2cfd=fd; *irqfd=irq;
    return 0;
}

static int do_nci(void){
    int i2cfd,irqfd;
    if(prep(&i2cfd,&irqfd)<0) return 1;

    printf("-- draining post-reset chatter --\n");
    nci_drain(i2cfd,irqfd,300,80);

    /* CORE_RESET_CMD: reset configuration */
    uint8_t core_reset[]={0x20,0x00,0x01,0x01};
    printf("-- CORE_RESET_CMD --\n"); hexdump("  >>",core_reset,4);
    if(nci_write(i2cfd,core_reset,4)<0) return 2;
    int rsp=nci_drain(i2cfd,irqfd,g_timeout,150);
    if(rsp<=0){
        printf("RESULT: chip did NOT answer CORE_RESET -- not alive on NCI.\n");
        printf("        try: --inv-reset / --inv-irq / check addr & lines.\n");
        return 3;
    }

    /* CORE_INIT_CMD: NCI 2.0 form (2-byte payload) */
    uint8_t core_init[]={0x20,0x01,0x02,0x00,0x00};
    printf("-- CORE_INIT_CMD (NCI 2.0) --\n"); hexdump("  >>",core_init,5);
    if(nci_write(i2cfd,core_init,5)<0) return 2;
    int ini=nci_drain(i2cfd,irqfd,g_timeout,150);
    if(ini<=0){
        /* fall back to NCI 1.0 form (0-byte payload) */
        uint8_t init10[]={0x20,0x01,0x00};
        printf("-- CORE_INIT_CMD (NCI 1.0 fallback) --\n"); hexdump("  >>",init10,3);
        nci_write(i2cfd,init10,3);
        ini=nci_drain(i2cfd,irqfd,g_timeout,150);
    }

    printf("RESULT: chip ALIVE on NCI -- CORE_RESET answered%s.\n",
           ini>0?" + CORE_INIT answered":" (CORE_INIT silent)");
    return 0;
}

static int do_drain(void){
    int i2cfd,irqfd;
    if(prep(&i2cfd,&irqfd)<0) return 1;
    printf("-- reading chip output (%d ms) --\n",g_timeout);
    int n=nci_drain(i2cfd,irqfd,g_timeout,150);
    printf("%d packet(s).\n",n);
    return 0;
}

/* write one NCI packet then drain replies; returns packets drained */
static int nci_cmd(int i2cfd,int irqfd,const char *label,
                   const uint8_t *cmd,int len,int idle_to){
    printf("-- %s --\n",label);
    if(nci_write(i2cfd,cmd,len)<0) return -1;
    return nci_drain(i2cfd,irqfd,g_timeout,idle_to);
}

/* ---- chip init (chip alive + RF enabled, no RF_DISCOVER_MAP yet) ----- */
static int nci_chip_init(int i2cfd,int irqfd){
    nci_drain(i2cfd,irqfd,500,150);                  /* unsolicited post-reset NTF */
    uint8_t core_reset[]={0x20,0x00,0x01,0x01};
    if(nci_cmd(i2cfd,irqfd,"CORE_RESET",core_reset,4,200)<=0){
        printf("ERROR: no CORE_RESET reply -- chip not alive.\n"); return -1; }
    uint8_t core_init[]={0x20,0x01,0x02,0x00,0x00};
    nci_cmd(i2cfd,irqfd,"CORE_INIT",core_init,5,200);
    /* ST proprietary PROP_NFC_MODE_SET powers up the RF subsystem; the
     * chip self-resets afterwards, so CORE_INIT must be sent again. */
    uint8_t mode_on[]={0x2F,0x02,0x02,0x02,0x01};
    nci_cmd(i2cfd,irqfd,"PROP_NFC_MODE_SET (RF enable)",mode_on,5,500);
    nci_cmd(i2cfd,irqfd,"CORE_INIT (after mode-set)",core_init,5,200);
    return 0;
}

/* Standard reader-mode RF_DISCOVER_MAP (poll, NFC Forum tag protocols). */
static const uint8_t rfmap_reader[]={
    0x21,0x00,0x10, 0x05,
    0x02,0x01,0x01,  0x03,0x01,0x01,  0x04,0x01,0x02,
    0x06,0x01,0x01,  0x05,0x01,0x03
};

/* Listen-mode RF_DISCOVER_MAP: ISO-DEP, listen mode, ISO-DEP interface. */
static const uint8_t rfmap_listen_iso[]={
    0x21,0x00,0x04, 0x01,
    0x04,0x02,0x02
};

/* nci_chip_init + the given RF_DISCOVER_MAP. Replaces the old nci_full_init. */
static int nci_full_init(int i2cfd,int irqfd){
    if(nci_chip_init(i2cfd,irqfd)<0) return -1;
    nci_cmd(i2cfd,irqfd,"RF_DISCOVER_MAP (reader)",
            rfmap_reader,sizeof rfmap_reader,200);
    return 0;
}

/* send RF_DISCOVER and wait for a tag to activate; ret 1 if found */
static int rf_discover_wait(int i2cfd,int irqfd){
    g_tag_found=0;
    uint8_t disc[]={0x21,0x03,0x09, 0x04,
        0x00,0x01, 0x01,0x01, 0x02,0x01, 0x06,0x01};
    nci_cmd(i2cfd,irqfd,"RF_DISCOVER (A/B/F/V passive poll)",disc,sizeof disc,200);
    if(!g_tag_found){
        int deadline = g_timeout<4000 ? 8000 : g_timeout;
        printf("-- waiting %d ms for a tag (hold it to the BACK of the phone) --\n",deadline);
        uint8_t buf[300]; int elapsed=0;
        while(elapsed<deadline && !g_tag_found){
            int nn=nci_read(i2cfd,irqfd,buf,500);
            if(nn==-2){ elapsed+=500; continue; }
            if(nn<0)  { elapsed+=50;  continue; }
            nci_decode(buf,nn);
        }
    }
    return g_tag_found;
}

static void rf_deactivate(int i2cfd,int irqfd){
    uint8_t deact[]={0x21,0x06,0x01,0x00};           /* RF_DEACTIVATE -> idle */
    nci_write(i2cfd,deact,4);
    nci_drain(i2cfd,irqfd,500,150);
}

static int do_poll(void){
    int i2cfd,irqfd;
    if(prep(&i2cfd,&irqfd)<0) return 1;
    if(nci_full_init(i2cfd,irqfd)<0) return 3;
    int found=rf_discover_wait(i2cfd,irqfd);
    rf_deactivate(i2cfd,irqfd);
    if(found){ printf("RESULT: tag detected and read OK.\n"); return 0; }
    printf("RESULT: no tag detected.\n");
    return 4;
}

/* ---- MIFARE Classic over NCI ------------------------------------------ */
/* send one NCI DATA packet, decode replies, capture last DATA payload */
static int data_xfer(int i2cfd,int irqfd,const uint8_t *tx,int txlen,
                     uint8_t *rx,int *rxlen,int *deact){
    *rxlen=0; *deact=0;
    if(nci_write(i2cfd,tx,txlen)<0) return -1;
    uint8_t buf[300]; int to=g_timeout;
    for(;;){
        int n=nci_read(i2cfd,irqfd,buf,to);
        if(n<0) break;
        nci_decode(buf,n);
        if((buf[0]&0xE0)==0x00 && n>=3){             /* DATA packet up from NFCC */
            int pl=buf[2]; if(pl>0){ memcpy(rx,buf+3,pl); *rxlen=pl; }
        }
        if(buf[0]==0x61 && buf[1]==0x06) *deact=1;   /* RF_DEACTIVATE_NTF */
        to=250;
    }
    return 0;
}

/* authenticate the sector containing `block` with a given 6-byte key A.
 * ST frame format (from ST-authored AOSP rw_mfc.cc): 60|block|UID(4)|key(6).
 * Success = a 1-byte DATA reply with status 0x00. `verbose` controls the
 * "-- MIFARE AUTH ..." progress lines (the dictionary attack runs quiet). */
static int mfc_auth_with_key(int i2cfd, int irqfd, int block,
                              const uint8_t key[6], int verbose){
    uint8_t pl[16]; int n=0;
    pl[n++]=0x60; pl[n++]=(uint8_t)block;
    int ul=g_uidlen?g_uidlen:4;
    memcpy(pl+n,g_uid,ul); n+=ul;
    memcpy(pl+n,key,6); n+=6;
    uint8_t pkt[24]; pkt[0]=0x00; pkt[1]=0x00; pkt[2]=(uint8_t)n;
    memcpy(pkt+3,pl,n);
    if(verbose){
        printf("-- MIFARE AUTH sector %d (block %d) key A ",block/4,block);
        for(int i=0;i<6;i++) printf("%02X",key[i]);
        printf(" --\n");
    }
    uint8_t rx[300]; int rxlen,deact;
    data_xfer(i2cfd,irqfd,pkt,3+n,rx,&rxlen,&deact);
    if(deact){
        if(verbose) printf("   AUTH failed -- RF link torn down.\n");
        return -1;
    }
    if(rxlen>=1 && rx[0]==0x00){
        if(verbose) printf("   AUTH OK (status 00).\n");
        return 0;
    }
    if(rxlen>=1){
        if(verbose) printf("   AUTH failed -- status 0x%02x.\n",rx[0]);
        return -1;
    }
    if(verbose) printf("   AUTH: no response.\n");
    return -1;
}

/* Convenience wrapper: authenticate with factory-default key A FF*6. */
static int mfc_auth(int i2cfd, int irqfd, int block){
    static const uint8_t k[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    return mfc_auth_with_key(i2cfd, irqfd, block, k, /*verbose*/1);
}

/* read one 16-byte block; if out16 != NULL, copy the block data there */
static int mfc_read(int i2cfd,int irqfd,int block,uint8_t *out16){
    uint8_t pkt[]={0x00,0x00,0x02,0x30,(uint8_t)block};   /* MIFARE READ 0x30 */
    uint8_t rx[300]; int rxlen,deact;
    data_xfer(i2cfd,irqfd,pkt,5,rx,&rxlen,&deact);
    if(deact){ printf("   block %2d : RF link torn down\n",block); return -1; }
    if(rxlen>=16){
        if(out16) memcpy(out16,rx,16);
        printf("   block %2d :",block);
        for(int i=0;i<16;i++) printf(" %02x",rx[i]);
        printf("%s\n", rxlen>16?"  (+status)":"");
        return 0;
    }
    printf("   block %2d : no data returned (rxlen=%d)\n",block,rxlen);
    return -1;
}

/* write 16 bytes to a block: MIFARE WRITE 0xA0 + block + 16 data bytes, in
 * one NCI DATA packet -- the 0x90 interface sequences the two air phases. */
static int mfc_write(int i2cfd,int irqfd,int block,const uint8_t *data){
    uint8_t pkt[3+18];
    pkt[0]=0x00; pkt[1]=0x00; pkt[2]=18;
    pkt[3]=0xA0; pkt[4]=(uint8_t)block;
    memcpy(pkt+5,data,16);
    printf("-- MIFARE WRITE block %d (A0 + 16 data bytes) --\n",block);
    uint8_t rx[300]; int rxlen,deact;
    data_xfer(i2cfd,irqfd,pkt,3+18,rx,&rxlen,&deact);
    if(deact){ printf("   write: RF link torn down\n"); return -1; }
    if(rxlen>=1 && rx[0]>=0xB0){                  /* NCI RF error status */
        printf("   write rejected -- status 0x%02x\n",rx[0]); return -1;
    }
    printf("   write sent (reply rxlen=%d, rx0=0x%02x) -- verifying by read-back\n",
           rxlen, rxlen?rx[0]:0);
    return 0;
}

static int do_read(int argc,char **argv){
    int first = argc>=1 ? atoi(argv[0]) : 0;
    int count = argc>=2 ? atoi(argv[1]) : 4;
    int i2cfd,irqfd;
    if(prep(&i2cfd,&irqfd)<0) return 1;
    if(nci_full_init(i2cfd,irqfd)<0) return 3;
    if(!rf_discover_wait(i2cfd,irqfd)){
        rf_deactivate(i2cfd,irqfd);
        printf("RESULT: no tag detected.\n"); return 4;
    }
    if(g_sak!=0x08)
        printf("NOTE: SAK 0x%02x is not MIFARE Classic 1K -- attempting anyway.\n",g_sak);

    int cur_sector=-1, read_ok=0, auth_fail=0;
    for(int b=first;b<first+count;b++){
        if(b/4 != cur_sector){
            if(mfc_auth(i2cfd,irqfd,(b/4)*4)<0){ auth_fail=1; break; }
            cur_sector=b/4;
        }
        if(mfc_read(i2cfd,irqfd,b,NULL)==0) read_ok++;
    }
    rf_deactivate(i2cfd,irqfd);
    if(auth_fail){
        printf("RESULT: MIFARE auth failed -- tag likely not using the "
               "default key A FF*6.\n");
        return 5;
    }
    if(read_ok>0){ printf("RESULT: read %d block(s) OK.\n",read_ok); return 0; }
    printf("RESULT: auth OK but no block data returned.\n");
    return 6;
}

static int do_write(int argc,char **argv){
    if(argc<1){ fprintf(stderr,"usage: stnfc write <block> [16 hex bytes]\n"); return 1; }
    int block=atoi(argv[0]);
    /* hard safety guard: never touch block 0 (manufacturer, read-only) or a
     * sector trailer (block 3,7,11,... -- bad access bits brick the sector). */
    if(block<=0 || block>62 || (block%4)==3){
        fprintf(stderr,"REFUSED: block %d is the manufacturer block or a sector "
                "trailer -- writing it can permanently brick the tag.\n",block);
        return 1;
    }
    uint8_t data[16];
    if(argc>=17){
        for(int j=0;j<16;j++) data[j]=(uint8_t)strtol(argv[1+j],0,16);
    } else {
        memcpy(data,"stnfc write OK!",16);            /* 15 chars + NUL = 16 */
    }

    int i2cfd,irqfd;
    if(prep(&i2cfd,&irqfd)<0) return 1;
    if(nci_full_init(i2cfd,irqfd)<0) return 3;
    if(!rf_discover_wait(i2cfd,irqfd)){
        rf_deactivate(i2cfd,irqfd);
        printf("RESULT: no tag detected.\n"); return 4;
    }
    if(g_sak!=0x08)
        printf("NOTE: SAK 0x%02x is not MIFARE Classic 1K -- attempting anyway.\n",g_sak);

    int rc;
    if(mfc_auth(i2cfd,irqfd,(block/4)*4)<0){
        printf("RESULT: auth failed.\n"); rc=5;
    } else if(mfc_write(i2cfd,irqfd,block,data)<0){
        printf("RESULT: write failed.\n"); rc=6;
    } else {
        uint8_t rb[16];                              /* read back & verify */
        printf("-- verify: re-reading block %d --\n",block);
        if(mfc_read(i2cfd,irqfd,block,rb)==0 && memcmp(rb,data,16)==0){
            printf("RESULT: WRITE VERIFIED -- read-back matches what was written.\n");
            rc=0;
        } else {
            printf("RESULT: write ACKed but read-back did not match.\n");
            rc=7;
        }
    }
    rf_deactivate(i2cfd,irqfd);
    return rc;
}

/* ---- MIFARE Classic 1K full dump -------------------------------------- */
static int do_dump(void){
    int i2cfd, irqfd;
    if(prep(&i2cfd, &irqfd) < 0) return 1;
    if(nci_full_init(i2cfd, irqfd) < 0) return 3;
    if(!rf_discover_wait(i2cfd, irqfd)){
        rf_deactivate(i2cfd, irqfd);
        printf("RESULT: no tag detected.\n"); return 4;
    }
    if(g_sak != 0x08){
        printf("RESULT: SAK 0x%02x is not MIFARE Classic 1K (need 0x08).\n",
               g_sak);
        rf_deactivate(i2cfd, irqfd); return 5;
    }

    int auth_ok = 0, bad_sectors = 0;
    int blocks_read = 0, blocks_tried = 0;

    for(int s = 0; s < 16; s++){
        printf("\n-- sector %d (blocks %d..%d) --\n", s, s*4, s*4+3);
        if(mfc_auth(i2cfd, irqfd, s * 4) < 0){
            printf("   sector %d: auth FAILED (key A != FF*6)\n", s);
            bad_sectors++;
            /* MIFARE auth-failure tears down the RF link -- re-activate. */
            if(!rf_discover_wait(i2cfd, irqfd)){
                printf("   no re-activation after auth failure -- aborting\n");
                break;
            }
            continue;
        }
        auth_ok++;
        for(int b = s*4; b < s*4 + 4; b++){
            blocks_tried++;
            if(mfc_read(i2cfd, irqfd, b, NULL) == 0) blocks_read++;
        }
    }
    rf_deactivate(i2cfd, irqfd);
    printf("\nRESULT: %d/16 sectors authed (%d need non-default keys), "
           "%d/%d blocks read.\n",
           auth_ok, bad_sectors, blocks_read, blocks_tried);
    return blocks_read > 0 ? 0 : 6;
}

/* ---- Type 4 NDEF tag emulation --------------------------------------- */

/* NFC Forum Type 4 NDEF tag application AID */
static const uint8_t t4t_ndef_aid[7] = {
    0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01
};

/* Type 4 Capability Container (CC) file -- v2.0, NDEF file id E1 04,
 * max file 0x0FFE, read access free, write access disabled. */
static const uint8_t t4t_cc[15] = {
    0x00, 0x0F,            /* CCLEN                          */
    0x20,                  /* mapping version 2.0            */
    0x00, 0x7F,            /* MLe -- max R-APDU data size    */
    0x00, 0x7F,            /* MLc -- max C-APDU data size    */
    0x04, 0x06,            /* NDEF File Control TLV: T, L    */
    0xE1, 0x04,            /* NDEF file ID                   */
    0x0F, 0xFE,            /* max NDEF size                  */
    0x00,                  /* read access:  free             */
    0xFF,                  /* write access: no write         */
};

/* NDEF file = 2-byte NLEN + NDEF message bytes. */
static uint8_t t4t_ndef[2 + 250];
static int     t4t_ndef_len;

/* Build the NDEF file from `payload`. URI prefixes get encoded as a
 * URI record with the matching prefix code; everything else becomes a
 * UTF-8 Text record. */
static void build_ndef(const char *payload){
    static const struct { uint8_t code; const char *p; } pfx[] = {
        {0x01, "http://www."},
        {0x02, "https://www."},
        {0x03, "http://"},
        {0x04, "https://"},
        {0x05, "tel:"},
        {0x06, "mailto:"},
    };
    uint8_t *out = t4t_ndef;
    int n = 2;                        /* leave 2 bytes for NLEN */
    int is_uri = 0; uint8_t code = 0; const char *rest = payload;

    for(unsigned i = 0; i < sizeof pfx / sizeof pfx[0]; i++){
        int len = strlen(pfx[i].p);
        if(strncmp(payload, pfx[i].p, len) == 0){
            is_uri = 1; code = pfx[i].code; rest = payload + len; break;
        }
    }

    if(is_uri){
        int rlen = strlen(rest);
        out[n++] = 0xD1;              /* MB|ME|SR|TNF=001 */
        out[n++] = 0x01;              /* type length */
        out[n++] = (uint8_t)(1 + rlen);
        out[n++] = 0x55;              /* type "U" */
        out[n++] = code;              /* URI abbreviation */
        memcpy(out + n, rest, rlen); n += rlen;
    } else {
        int rlen = strlen(payload);
        out[n++] = 0xD1;
        out[n++] = 0x01;
        out[n++] = (uint8_t)(3 + rlen);
        out[n++] = 0x54;              /* type "T" */
        out[n++] = 0x02;              /* lang code length = 2, UTF-8 */
        out[n++] = 'e'; out[n++] = 'n';
        memcpy(out + n, payload, rlen); n += rlen;
    }

    int msglen = n - 2;
    out[0] = (uint8_t)(msglen >> 8);
    out[1] = (uint8_t)(msglen & 0xFF);
    t4t_ndef_len = n;
}

/* Type 4 tag selected-file state. */
enum { T4T_NONE, T4T_CC, T4T_NDEF };
static int t4t_state;

/* Process one C-APDU; build the R-APDU. Returns response length. */
static int t4t_apdu(const uint8_t *a, int n, uint8_t *r){
    /* SELECT by name -- NDEF tag application AID */
    if(n >= 13 && a[0]==0x00 && a[1]==0xA4 && a[2]==0x04 && a[3]==0x00 &&
       a[4]==0x07 && memcmp(a + 5, t4t_ndef_aid, 7) == 0){
        t4t_state = T4T_NONE;
        printf("  <- SELECT NDEF app   -> 90 00\n");
        r[0]=0x90; r[1]=0x00; return 2;
    }
    /* SELECT by file ID (P1=00, P2=0C "no FCI") */
    if(n >= 7 && a[0]==0x00 && a[1]==0xA4 && a[2]==0x00 && a[3]==0x0C &&
       a[4]==0x02){
        uint16_t fid = (a[5] << 8) | a[6];
        if(fid == 0xE103){
            t4t_state = T4T_CC;
            printf("  <- SELECT CC file    -> 90 00\n");
            r[0]=0x90; r[1]=0x00; return 2;
        }
        if(fid == 0xE104){
            t4t_state = T4T_NDEF;
            printf("  <- SELECT NDEF file  -> 90 00\n");
            r[0]=0x90; r[1]=0x00; return 2;
        }
        printf("  <- SELECT %04x  -> 6A 82 (not found)\n", fid);
        r[0]=0x6A; r[1]=0x82; return 2;
    }
    /* READ BINARY: P1P2 = offset, Le = length */
    if(n >= 5 && a[0]==0x00 && a[1]==0xB0){
        int off = (a[2] << 8) | a[3];
        int le  = a[4] ? a[4] : 256;
        const uint8_t *src = NULL; int srclen = 0;
        if(t4t_state == T4T_CC)   { src = t4t_cc;   srclen = sizeof t4t_cc; }
        if(t4t_state == T4T_NDEF) { src = t4t_ndef; srclen = t4t_ndef_len; }
        if(!src){
            printf("  <- READ before SELECT -> 69 86\n");
            r[0]=0x69; r[1]=0x86; return 2;
        }
        if(off >= srclen){
            printf("  <- READ off=%d past file -> 6B 00\n", off);
            r[0]=0x6B; r[1]=0x00; return 2;
        }
        if(off + le > srclen) le = srclen - off;
        memcpy(r, src + off, le);
        r[le]=0x90; r[le+1]=0x00;
        printf("  <- READ %-4s off=%d le=%d -> %d bytes + 90 00\n",
               t4t_state == T4T_CC ? "CC" : "NDEF", off, le, le);
        return le + 2;
    }
    printf("  <- unknown APDU (len=%d) -> 6D 00\n", n);
    r[0]=0x6D; r[1]=0x00; return 2;
}

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int s){ (void)s; g_stop = 1; }

/* Build a WFA WSC Wi-Fi NDEF record into t4t_ndef (with NLEN prefix). */
static void build_ndef_wifi(const char *ssid, const char *psk, int wpa2){
    int slen = (int)strlen(ssid);
    int plen = (int)strlen(psk);

    /* WFA WSC Credential inner TLVs */
    uint8_t inner[256]; int n = 0;
    /* Network Index */
    inner[n++]=0x10; inner[n++]=0x26; inner[n++]=0x00; inner[n++]=0x01;
    inner[n++]=0x01;
    /* SSID */
    inner[n++]=0x10; inner[n++]=0x45;
    inner[n++]=(uint8_t)(slen>>8); inner[n++]=(uint8_t)(slen&0xFF);
    memcpy(inner+n, ssid, slen); n += slen;
    /* Auth Type */
    int auth = !plen ? 0x0001 : (wpa2 ? 0x0020 : 0x0002);
    inner[n++]=0x10; inner[n++]=0x03; inner[n++]=0x00; inner[n++]=0x02;
    inner[n++]=(uint8_t)(auth>>8); inner[n++]=(uint8_t)(auth&0xFF);
    /* Encryption Type */
    int enc = !plen ? 0x0001 : 0x0008;
    inner[n++]=0x10; inner[n++]=0x0F; inner[n++]=0x00; inner[n++]=0x02;
    inner[n++]=(uint8_t)(enc>>8); inner[n++]=(uint8_t)(enc&0xFF);
    /* Network Key */
    inner[n++]=0x10; inner[n++]=0x27;
    inner[n++]=(uint8_t)(plen>>8); inner[n++]=(uint8_t)(plen&0xFF);
    if(plen){ memcpy(inner+n, psk, plen); n += plen; }
    /* MAC Address - broadcast */
    inner[n++]=0x10; inner[n++]=0x20; inner[n++]=0x00; inner[n++]=0x06;
    inner[n++]=0xFF; inner[n++]=0xFF; inner[n++]=0xFF;
    inner[n++]=0xFF; inner[n++]=0xFF; inner[n++]=0xFF;

    /* Wrap as a Credential TLV */
    uint8_t cred[300]; int c = 0;
    cred[c++]=0x10; cred[c++]=0x0E;
    cred[c++]=(uint8_t)(n>>8); cred[c++]=(uint8_t)(n&0xFF);
    memcpy(cred+c, inner, n); c += n;

    /* NDEF record: TNF=MIME (0x02), type "application/vnd.wfa.wsc" */
    static const char mime[] = "application/vnd.wfa.wsc";
    int mlen = (int)sizeof mime - 1;
    uint8_t *out = t4t_ndef;
    int rn = 2;                       /* leave 2 bytes for NLEN */
    out[rn++] = 0xD2;                 /* MB|ME|SR|TNF=2 */
    out[rn++] = (uint8_t)mlen;        /* type length */
    out[rn++] = (uint8_t)c;           /* payload length (SR) */
    memcpy(out+rn, mime, mlen); rn += mlen;
    memcpy(out+rn, cred, c); rn += c;

    int msglen = rn - 2;
    out[0] = (uint8_t)(msglen >> 8);
    out[1] = (uint8_t)(msglen & 0xFF);
    t4t_ndef_len = rn;
}

/* Apply --la-nfcid1 if set: send NCI CORE_SET_CONFIG TLV 0x33 (LA_NFCID1)
 * so the chip presents the given UID in NFC-A listen mode. Whether the
 * chip honors it is firmware-specific. */
static void apply_la_nfcid1(int i2cfd, int irqfd){
    if(g_la_nfcid1_len == 0) return;
    uint8_t cmd[24]; int n = 0;
    cmd[n++] = 0x20; cmd[n++] = 0x02;                   /* CORE_SET_CONFIG */
    cmd[n++] = (uint8_t)(1 + 2 + g_la_nfcid1_len);      /* payload length */
    cmd[n++] = 0x01;                                    /* 1 TLV */
    cmd[n++] = 0x33;                                    /* LA_NFCID1 */
    cmd[n++] = (uint8_t)g_la_nfcid1_len;
    memcpy(cmd + n, g_la_nfcid1, g_la_nfcid1_len);
    n += g_la_nfcid1_len;
    printf("-- LA_NFCID1 spoof = ");
    for(int i = 0; i < g_la_nfcid1_len; i++) printf("%02X ", g_la_nfcid1[i]);
    printf("--\n");
    nci_cmd(i2cfd, irqfd, "CORE_SET_CONFIG (LA_NFCID1)", cmd, n, 200);
}

/* Shared listen-mode loop: serves t4t_ndef contents to readers as a
 * Type 4 tag, via the t4t_apdu state machine. */
static int emulate_t4_listen(int i2cfd, int irqfd, const char *banner){
    apply_la_nfcid1(i2cfd, irqfd);
    nci_cmd(i2cfd, irqfd, "RF_DISCOVER_MAP (ISO-DEP listen)",
            rfmap_listen_iso, sizeof rfmap_listen_iso, 200);
    uint8_t disc[] = { 0x21, 0x03, 0x03,  0x01,  0x80, 0x01 };
    nci_cmd(i2cfd, irqfd, "RF_DISCOVER (NFC-A passive listen)",
            disc, sizeof disc, 200);

    int deadline = g_timeout < 5000 ? 30000 : g_timeout;
    printf("\n*** %s ***\n", banner);
    printf("    Tap a reader to the BACK of the phone.\n");
    printf("    Window: %d ms (use --timeout <ms> to extend). Ctrl+C to stop.\n\n",
           deadline);

    signal(SIGINT, on_sigint);
    g_stop = 0;
    int activated = 0, taps = 0, elapsed = 0;
    uint8_t buf[300], resp[300];

    while(!g_stop && elapsed < deadline){
        int n = nci_read(i2cfd, irqfd, buf, 500);
        if(n == -2){ elapsed += 500; continue; }
        if(n < 0)  { elapsed += 50;  continue; }
        nci_decode(buf, n);

        if(buf[0] == 0x61 && buf[1] == 0x05){
            activated = 1;
            t4t_state = T4T_NONE;
            taps++;
            printf("\n--- reader detected (tap #%d) ---\n", taps);
        } else if(buf[0] == 0x61 && buf[1] == 0x06){
            if(activated){
                printf("--- reader left field ---\n\n");
                activated = 0;
            }
        } else if((buf[0] & 0xE0) == 0x00 && n >= 3 && activated){
            int plen = buf[2];
            int rlen = t4t_apdu(buf + 3, plen, resp);
            uint8_t pkt[3 + 260];
            pkt[0] = 0x00; pkt[1] = 0x00; pkt[2] = (uint8_t)rlen;
            memcpy(pkt + 3, resp, rlen);
            nci_write(i2cfd, pkt, 3 + rlen);
        }
    }

    printf("\nstopping... (%d reader tap(s) handled)\n", taps);
    return taps;
}

static int do_emulate_ndef(int argc, char **argv){
    const char *payload = (argc >= 1)
        ? argv[0]
        : "https://github.com/miromraz/pmaports-sunfish";
    build_ndef(payload);
    printf("NDEF payload: \"%s\"  (%d bytes)\n", payload, t4t_ndef_len - 2);

    int i2cfd, irqfd;
    if(prep(&i2cfd, &irqfd) < 0) return 1;
    if(nci_chip_init(i2cfd, irqfd) < 0) return 3;
    char banner[200];
    snprintf(banner, sizeof banner, "Emulating Type 4 NDEF tag");
    int taps = emulate_t4_listen(i2cfd, irqfd, banner);
    rf_deactivate(i2cfd, irqfd);
    return taps > 0 ? 0 : 4;
}

/* Build a vCard 3.0 NDEF MIME record into t4t_ndef (with NLEN prefix). */
static void build_ndef_vcard(const char *name, const char *phone,
                              const char *email){
    char body[600];
    int bn = snprintf(body, sizeof body,
        "BEGIN:VCARD\r\n"
        "VERSION:3.0\r\n"
        "FN:%s\r\n", name);
    if(phone && phone[0])
        bn += snprintf(body + bn, sizeof body - bn, "TEL:%s\r\n", phone);
    if(email && email[0])
        bn += snprintf(body + bn, sizeof body - bn, "EMAIL:%s\r\n", email);
    bn += snprintf(body + bn, sizeof body - bn, "END:VCARD\r\n");
    if(bn < 0 || bn >= (int)sizeof body) bn = (int)sizeof body - 1;

    static const char mime[] = "text/vcard";
    int mlen = (int)sizeof mime - 1;
    uint8_t *out = t4t_ndef;
    int rn = 2;                              /* NLEN prefix */
    if(bn < 256){
        out[rn++] = 0xD2;                    /* MB|ME|SR|TNF=2 */
        out[rn++] = (uint8_t)mlen;
        out[rn++] = (uint8_t)bn;
    } else {                                 /* long-record form */
        out[rn++] = 0xC2;
        out[rn++] = (uint8_t)mlen;
        out[rn++] = 0; out[rn++] = 0;
        out[rn++] = (uint8_t)(bn >> 8);
        out[rn++] = (uint8_t)(bn & 0xFF);
    }
    memcpy(out + rn, mime, mlen); rn += mlen;
    memcpy(out + rn, body, bn);   rn += bn;

    int msglen = rn - 2;
    out[0] = (uint8_t)(msglen >> 8);
    out[1] = (uint8_t)(msglen & 0xFF);
    t4t_ndef_len = rn;
}

static int do_emulate_vcard(int argc, char **argv){
    if(argc < 1){
        fprintf(stderr,
            "usage: stnfc emulate-vcard <name> [phone] [email]\n"
            "  Phone shows up as an NFC vCard tag; receiver offers to add\n"
            "  the contact. Use quotes around the name if it contains spaces.\n");
        return 1;
    }
    const char *name  = argv[0];
    const char *phone = (argc >= 2) ? argv[1] : "";
    const char *email = (argc >= 3) ? argv[2] : "";
    build_ndef_vcard(name, phone, email);
    printf("vCard NDEF: FN=\"%s\"  TEL=\"%s\"  EMAIL=\"%s\"  (%d bytes)\n",
           name, phone, email, t4t_ndef_len - 2);

    int i2cfd, irqfd;
    if(prep(&i2cfd, &irqfd) < 0) return 1;
    if(nci_chip_init(i2cfd, irqfd) < 0) return 3;
    char banner[200];
    snprintf(banner, sizeof banner, "Emulating vCard tag (FN=\"%s\")", name);
    int taps = emulate_t4_listen(i2cfd, irqfd, banner);
    rf_deactivate(i2cfd, irqfd);
    return taps > 0 ? 0 : 4;
}

static int do_emulate_wifi(int argc, char **argv){
    if(argc < 1){
        fprintf(stderr,
            "usage: stnfc emulate-wifi <SSID> [password] [OPEN]\n"
            "  Phone shows up as an NFC Wi-Fi-config tag; a receiver phone\n"
            "  joins the named network on tap. Open networks need no\n"
            "  password (or pass OPEN explicitly).\n");
        return 1;
    }
    const char *ssid = argv[0];
    const char *psk = (argc >= 2) ? argv[1] : "";
    int open = (argc >= 3 && strcasecmp(argv[2], "OPEN") == 0) || !psk[0];
    if(open) psk = "";

    build_ndef_wifi(ssid, psk, !open);
    printf("Wi-Fi NDEF: SSID=\"%s\", security=%s, payload=%d bytes\n",
           ssid, open ? "open" : "WPA2-PSK", t4t_ndef_len - 2);

    int i2cfd, irqfd;
    if(prep(&i2cfd, &irqfd) < 0) return 1;
    if(nci_chip_init(i2cfd, irqfd) < 0) return 3;
    char banner[200];
    snprintf(banner, sizeof banner,
             "Emulating Wi-Fi tag (SSID=\"%s\", %s)",
             ssid, open ? "open" : "WPA2-PSK");
    int taps = emulate_t4_listen(i2cfd, irqfd, banner);
    rf_deactivate(i2cfd, irqfd);
    return taps > 0 ? 0 : 4;
}

/* ---- NDEF parsing ----------------------------------------------------- */

/* NFC Forum URI prefix codes (NDEF URI record). */
static const char *uri_prefix(uint8_t code){
    static const char *p[] = {
        "", "http://www.", "https://www.", "http://", "https://",
        "tel:", "mailto:", "ftp://anonymous:anonymous@", "ftp://ftp.",
        "ftps://", "sftp://", "smb://", "nfs://", "ftp://", "dav://",
        "news:", "telnet://", "imap:", "rtsp://", "urn:", "pop:",
        "sip:", "sips:", "tftp:", "btspp://", "btl2cap://",
        "btgoep://", "tcpobex://", "irdaobex://", "file://",
        "urn:epc:id:", "urn:epc:tag:", "urn:epc:pat:", "urn:epc:raw:",
        "urn:epc:", "urn:nfc:",
    };
    return code < sizeof p / sizeof p[0] ? p[code] : "";
}

/* Print one NDEF record; return bytes consumed (0 on parse error). */
static int ndef_print_record(const uint8_t *r, int len){
    if(len < 3) return 0;
    uint8_t hdr = r[0];
    int sr  = !!(hdr & 0x10);
    int il  = !!(hdr & 0x08);
    int tnf =   hdr & 0x07;
    int p = 1;
    if(p >= len) return 0;
    int tlen = r[p++];
    int plen;
    if(sr){ if(p>=len) return 0; plen = r[p++]; }
    else  { if(p+4>len) return 0;
            plen = (r[p]<<24)|(r[p+1]<<16)|(r[p+2]<<8)|r[p+3]; p+=4; }
    int ilen = 0;
    if(il){ if(p>=len) return 0; ilen = r[p++]; }
    if(p + tlen + ilen + plen > len) return 0;
    const uint8_t *typ = r + p; p += tlen;
    p += ilen;                                  /* skip ID */
    const uint8_t *pay = r + p; p += plen;

    printf("  NDEF record [TNF=%d", tnf);
    if(tlen) printf(", type=\"%.*s\"", tlen, typ);
    printf(", %d-byte payload]\n", plen);

    if(tnf==1 && tlen==1 && typ[0]=='U' && plen>=1){
        printf("    URI : %s%.*s\n", uri_prefix(pay[0]), plen-1, pay+1);
    } else if(tnf==1 && tlen==1 && typ[0]=='T' && plen>=1){
        int slen = pay[0] & 0x3F;
        if(1+slen <= plen)
            printf("    Text (lang=%.*s): %.*s\n",
                   slen, pay+1, plen-1-slen, pay+1+slen);
    } else {
        printf("    raw :");
        int show = plen < 48 ? plen : 48;
        for(int i=0;i<show;i++) printf(" %02x", pay[i]);
        if(plen>48) printf(" ...");
        printf("\n");
    }
    return p;
}

static void ndef_print_message(const uint8_t *msg, int len){
    int p = 0;
    while(p < len){
        int n = ndef_print_record(msg + p, len - p);
        if(n <= 0){ printf("  (NDEF parse error at offset %d)\n", p); break; }
        p += n;
    }
}

/* Find the NDEF TLV (tag 0x03) in a TLV-formatted user memory buffer. */
static int ndef_find_tlv(const uint8_t *buf, int len, int *out_off, int *out_len){
    int p = 0;
    while(p < len){
        uint8_t t = buf[p++];
        if(t == 0x00) continue;             /* null TLV (padding) */
        if(t == 0xFE) return -1;            /* terminator */
        if(p >= len) return -1;
        int l = buf[p++];
        if(l == 0xFF){                      /* 3-byte length form */
            if(p + 2 > len) return -1;
            l = (buf[p] << 8) | buf[p+1]; p += 2;
        }
        if(p + l > len) return -1;
        if(t == 0x03){ *out_off = p; *out_len = l; return 0; }
        p += l;
    }
    return -1;
}

/* ---- Type 2 (NTAG/Ultralight) read & write ---------------------------- */

/* T2T READ <block> returns 16 bytes (the block + 3 following). */
static int t2t_read(int i2cfd, int irqfd, int block, uint8_t *out16){
    uint8_t pkt[]={0x00,0x00,0x02, 0x30, (uint8_t)block};
    uint8_t rx[300]; int rxlen, deact;
    data_xfer(i2cfd, irqfd, pkt, sizeof pkt, rx, &rxlen, &deact);
    if(deact || rxlen < 16) return -1;
    memcpy(out16, rx, 16);
    return 0;
}

/* T2T WRITE <block> 4 bytes -- chip returns 4-bit ACK 0x0A on success. */
static int t2t_write_block(int i2cfd, int irqfd, int block, const uint8_t *data4){
    uint8_t pkt[]={0x00,0x00,0x06, 0xA2, (uint8_t)block,
                   data4[0], data4[1], data4[2], data4[3]};
    uint8_t rx[300]; int rxlen, deact;
    data_xfer(i2cfd, irqfd, pkt, sizeof pkt, rx, &rxlen, &deact);
    if(deact) return -1;
    if(rxlen >= 1 && (rx[0] & 0x0F) == 0x0A) return 0;
    if(rxlen >= 1) printf("  T2T block %d: NAK rx0=0x%02x\n", block, rx[0]);
    return -1;
}

/* Parse the CC at block 3 and read user memory; returns user-memory bytes. */
static int t2t_load_user_memory(int i2cfd, int irqfd,
                                uint8_t *out, int outsz, int *rw_access){
    uint8_t b[16];
    if(t2t_read(i2cfd, irqfd, 3, b) < 0){
        printf("  T2T: failed to read CC at block 3\n"); return -1;
    }
    if(b[0] != 0xE1){
        printf("  T2T: CC magic 0x%02x != 0xE1 -- tag not NDEF-formatted\n", b[0]);
        return -1;
    }
    int total = b[2] * 8;
    *rw_access = b[3];
    printf("  T2T CC: ver=0x%02x size=%d bytes access=0x%02x\n",
           b[1], total, b[3]);

    int cap = total < outsz ? total : outsz;
    /* The READ at block 3 also returned blocks 4,5,6 -- 12 bytes of user mem. */
    int got = 0;
    int copy = cap < 12 ? cap : 12;
    memcpy(out, b + 4, copy); got += copy;

    int blk = 7;
    while(got < cap){
        uint8_t cur[16];
        if(t2t_read(i2cfd, irqfd, blk, cur) < 0) break;
        int c = cap - got; if(c > 16) c = 16;
        memcpy(out + got, cur, c); got += c;
        blk += 4;
    }
    return got;
}

/* ---- Type 4 (ISO-DEP) NDEF read --------------------------------------- */

/* Send an APDU C-APDU over the activated ISO-DEP connection, return the
 * response payload (without the trailing SW1 SW2); -1 on error.
 * c_apdu includes only the C-APDU bytes (no NCI header). */
static int t4t_send_apdu(int i2cfd, int irqfd,
                         const uint8_t *c, int clen,
                         uint8_t *out, int *outlen){
    uint8_t pkt[3 + 260];
    if(clen > 255) return -1;
    pkt[0]=0x00; pkt[1]=0x00; pkt[2]=(uint8_t)clen;
    memcpy(pkt + 3, c, clen);

    uint8_t rx[300]; int rxlen, deact;
    data_xfer(i2cfd, irqfd, pkt, 3 + clen, rx, &rxlen, &deact);
    if(deact || rxlen < 2) return -1;
    int sw1 = rx[rxlen-2], sw2 = rx[rxlen-1];
    if(sw1 != 0x90 || sw2 != 0x00){
        printf("  T4T APDU -> SW=%02X%02X\n", sw1, sw2);
        return -1;
    }
    *outlen = rxlen - 2;
    if(*outlen > 0) memcpy(out, rx, *outlen);
    return 0;
}

static int t4t_ndef_read(int i2cfd, int irqfd){
    uint8_t rx[300]; int rxlen;

    /* SELECT NDEF tag application */
    static const uint8_t s_aid[] = {
        0x00, 0xA4, 0x04, 0x00, 0x07,
        0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00
    };
    if(t4t_send_apdu(i2cfd, irqfd, s_aid, sizeof s_aid, rx, &rxlen) < 0){
        printf("  T4T: SELECT NDEF app failed\n"); return -1;
    }
    printf("  T4T: NDEF app selected\n");

    /* SELECT CC file E1 03 */
    static const uint8_t s_cc[] = {0x00,0xA4,0x00,0x0C,0x02,0xE1,0x03};
    if(t4t_send_apdu(i2cfd, irqfd, s_cc, sizeof s_cc, rx, &rxlen) < 0){
        printf("  T4T: SELECT CC failed\n"); return -1;
    }
    /* READ CC */
    static const uint8_t r_cc[] = {0x00,0xB0,0x00,0x00,0x0F};
    if(t4t_send_apdu(i2cfd, irqfd, r_cc, sizeof r_cc, rx, &rxlen) < 0
       || rxlen < 15){
        printf("  T4T: READ CC failed\n"); return -1;
    }
    uint16_t ndef_id = (rx[9] << 8) | rx[10];
    uint16_t max_ndef = (rx[11] << 8) | rx[12];
    printf("  T4T CC: NDEF file 0x%04x, max %u bytes\n", ndef_id, max_ndef);

    /* SELECT NDEF file */
    uint8_t s_nd[] = {0x00,0xA4,0x00,0x0C,0x02,
                      (uint8_t)(ndef_id >> 8), (uint8_t)ndef_id};
    if(t4t_send_apdu(i2cfd, irqfd, s_nd, sizeof s_nd, rx, &rxlen) < 0){
        printf("  T4T: SELECT NDEF file failed\n"); return -1;
    }
    /* READ NLEN */
    static const uint8_t r_nl[] = {0x00,0xB0,0x00,0x00,0x02};
    if(t4t_send_apdu(i2cfd, irqfd, r_nl, sizeof r_nl, rx, &rxlen) < 0
       || rxlen < 2){
        printf("  T4T: READ NLEN failed\n"); return -1;
    }
    int nlen = (rx[0] << 8) | rx[1];
    printf("  T4T: NDEF message length = %d bytes\n", nlen);
    if(nlen == 0){ printf("  (empty NDEF)\n"); return 0; }

    /* READ NDEF data in <=0x7F chunks */
    uint8_t msg[1024]; int got = 0;
    while(got < nlen){
        int want = nlen - got; if(want > 0x7F) want = 0x7F;
        uint8_t r_md[] = {0x00, 0xB0,
                          (uint8_t)((2 + got) >> 8), (uint8_t)(2 + got),
                          (uint8_t)want};
        if(t4t_send_apdu(i2cfd, irqfd, r_md, sizeof r_md, rx, &rxlen) < 0
           || rxlen < want){
            printf("  T4T: READ NDEF data failed at offset %d\n", got);
            return -1;
        }
        memcpy(msg + got, rx, want); got += want;
    }
    printf("\nNDEF message:\n");
    ndef_print_message(msg, nlen);
    return 0;
}

/* ---- ndef-read / ndef-write subcommands ------------------------------- */

static int do_ndef_read(void){
    int i2cfd, irqfd;
    if(prep(&i2cfd, &irqfd) < 0) return 1;
    if(nci_full_init(i2cfd, irqfd) < 0) return 3;
    if(!rf_discover_wait(i2cfd, irqfd)){
        rf_deactivate(i2cfd, irqfd);
        printf("RESULT: no tag detected.\n"); return 4;
    }

    int r = -1;
    if(g_rf_proto == 0x02){
        printf("\n-- Type 2 (NTAG / Ultralight) NDEF read --\n");
        uint8_t mem[256]; int access;
        int mlen = t2t_load_user_memory(i2cfd, irqfd, mem, sizeof mem, &access);
        if(mlen > 0){
            int off, nlen;
            if(ndef_find_tlv(mem, mlen, &off, &nlen) == 0){
                printf("  NDEF TLV: %d-byte message at offset %d\n\n", nlen, off);
                ndef_print_message(mem + off, nlen);
                r = 0;
            } else {
                printf("  no NDEF TLV in user memory\n");
            }
        }
    } else if(g_rf_proto == 0x04){
        printf("\n-- Type 4 (ISO-DEP) NDEF read --\n");
        r = t4t_ndef_read(i2cfd, irqfd);
    } else {
        printf("\n-- RF protocol 0x%02x: not a supported NDEF tag type --\n",
               g_rf_proto);
        printf("   Supported: 0x02 (Type 2 NTAG/Ultralight), 0x04 (Type 4 ISO-DEP).\n");
        printf("   MIFARE Classic NDEF needs MAD parsing (not yet implemented).\n");
    }
    rf_deactivate(i2cfd, irqfd);
    return r == 0 ? 0 : 6;
}

/* Send a C-APDU and return the full R-APDU (data + SW), unfiltered. */
static int t4t_send_apdu_raw(int i2cfd, int irqfd,
                             const uint8_t *c, int clen,
                             uint8_t *out, int *outlen){
    if(clen > 255) return -1;
    uint8_t pkt[3 + 260];
    pkt[0] = 0x00; pkt[1] = 0x00; pkt[2] = (uint8_t)clen;
    memcpy(pkt + 3, c, clen);

    uint8_t rx[300]; int rxlen, deact;
    data_xfer(i2cfd, irqfd, pkt, 3 + clen, rx, &rxlen, &deact);
    if(deact) return -1;
    if(rxlen < 2) return -1;
    if(rxlen > 300) rxlen = 300;
    memcpy(out, rx, rxlen);
    *outlen = rxlen;
    return 0;
}

static const char *sw_name(int sw1, int sw2){
    if(sw1==0x90 && sw2==0x00) return "OK";
    if(sw1==0x61)              return "OK, more bytes available (GET RESPONSE)";
    if(sw1==0x62 || sw1==0x63) return "warning";
    if(sw1==0x67)              return "wrong Lc/Le";
    if(sw1==0x69 && sw2==0x82) return "security status not satisfied";
    if(sw1==0x69 && sw2==0x84) return "referenced data invalidated";
    if(sw1==0x6A && sw2==0x80) return "incorrect parameters in data field";
    if(sw1==0x6A && sw2==0x81) return "function not supported";
    if(sw1==0x6A && sw2==0x82) return "file or application not found";
    if(sw1==0x6A && sw2==0x86) return "incorrect P1 P2";
    if(sw1==0x6D)              return "INS not supported";
    if(sw1==0x6E)              return "CLA not supported";
    if(sw1==0x6F)              return "internal card error";
    return "unknown SW";
}

/* Send one APDU and pretty-print the response. `n` is the APDU index for
 * logging in multi-APDU chains. Returns 0 on success (any SW). */
static int apdu_send_print(int i2cfd, int irqfd, int n,
                            const uint8_t *apdu, int alen){
    printf("\n-- C-APDU #%d (%d bytes) --\n  ->", n, alen);
    for(int j = 0; j < alen; j++) printf(" %02x", apdu[j]);
    printf("\n");
    uint8_t resp[300]; int rlen;
    if(t4t_send_apdu_raw(i2cfd, irqfd, apdu, alen, resp, &rlen) < 0){
        printf("  <- transceive failed (RF link torn down?)\n");
        return -1;
    }
    int sw1 = resp[rlen - 2], sw2 = resp[rlen - 1];
    int dlen = rlen - 2;
    printf("-- R-APDU #%d (%d byte%s) --\n", n, rlen, rlen==1?"":"s");
    if(dlen > 0){
        printf("  <- data (%d):", dlen);
        for(int j = 0; j < dlen && j < 80; j++) printf(" %02x", resp[j]);
        if(dlen > 80) printf(" ...");
        printf("\n     ascii: ");
        for(int j = 0; j < dlen && j < 80; j++)
            putchar(resp[j] >= 0x20 && resp[j] < 0x7F ? resp[j] : '.');
        printf("\n");
    }
    printf("  <- SW=%02X%02X   (%s)\n", sw1, sw2, sw_name(sw1, sw2));
    return 0;
}

static int do_apdu(int argc, char **argv){
    if(argc < 4){
        fprintf(stderr,
            "usage: stnfc apdu HH HH HH HH [...] [ ';' HH HH ... ] ...\n"
            "  Sends one or more APDUs in a single ISO-DEP activation.\n"
            "  Separate multiple APDUs with the literal token ';'.\n"
            "  Example -- DESFire select-app + authenticate in one session:\n"
            "  stnfc apdu 90 5A 00 00 03 D0 02 F4 00 ';' 90 AA 00 00 01 00 00\n");
        return 1;
    }
    /* Parse APDUs separated by ';' tokens into a list. */
    #define MAX_APDUS 16
    uint8_t apdus[MAX_APDUS][260]; int alens[MAX_APDUS]; int an = 0;
    int cur = 0;
    for(int j = 0; j < argc; j++){
        if(strcmp(argv[j], ";") == 0){
            if(cur > 0){
                alens[an++] = cur; cur = 0;
                if(an >= MAX_APDUS){
                    fprintf(stderr,"too many APDUs (max %d)\n", MAX_APDUS);
                    return 1;
                }
            }
            continue;
        }
        char *end;
        long v = strtol(argv[j], &end, 16);
        if(*end != 0 || v < 0 || v > 255){
            fprintf(stderr,"invalid hex at position %d: %s\n", j, argv[j]);
            return 1;
        }
        if(cur >= 260){
            fprintf(stderr,"APDU too long at position %d\n", j); return 1;
        }
        apdus[an][cur++] = (uint8_t)v;
    }
    if(cur > 0){ alens[an++] = cur; }
    if(an == 0){
        fprintf(stderr,"no APDUs given\n"); return 1;
    }

    int i2cfd, irqfd;
    if(prep(&i2cfd, &irqfd) < 0) return 1;
    if(nci_full_init(i2cfd, irqfd) < 0) return 3;
    if(!rf_discover_wait(i2cfd, irqfd)){
        rf_deactivate(i2cfd, irqfd);
        printf("RESULT: no tag detected.\n"); return 4;
    }
    if(g_rf_proto != 0x04){
        printf("RESULT: tag is not ISO-DEP (RF proto 0x%02x) -- APDU needs Type 4.\n",
               g_rf_proto);
        rf_deactivate(i2cfd, irqfd); return 5;
    }

    for(int j = 0; j < an; j++){
        if(apdu_send_print(i2cfd, irqfd, j+1, apdus[j], alens[j]) < 0){
            printf("RESULT: chain aborted at APDU #%d (link torn down).\n", j+1);
            rf_deactivate(i2cfd, irqfd);
            return 6;
        }
    }
    rf_deactivate(i2cfd, irqfd);
    return 0;
}

static int do_ndef_write(int argc, char **argv){
    if(argc < 1){
        fprintf(stderr,"usage: stnfc ndef-write <url-or-text>\n");
        return 1;
    }
    const char *payload = argv[0];

    /* Build the NDEF message into t4t_ndef (reuses the same buffer; the
     * NLEN prefix at t4t_ndef[0..1] is for Type 4 only and gets stripped
     * here -- the Type 2 TLV uses its own length). */
    build_ndef(payload);
    int msglen = t4t_ndef_len - 2;
    const uint8_t *msg = t4t_ndef + 2;

    /* Wrap in an NDEF TLV: 0x03 LL <message> 0xFE */
    uint8_t tlv[4 + 250]; int tlvlen = 0;
    tlv[tlvlen++] = 0x03;
    if(msglen < 0xFF){
        tlv[tlvlen++] = (uint8_t)msglen;
    } else {
        tlv[tlvlen++] = 0xFF;
        tlv[tlvlen++] = (uint8_t)(msglen >> 8);
        tlv[tlvlen++] = (uint8_t)msglen;
    }
    memcpy(tlv + tlvlen, msg, msglen); tlvlen += msglen;
    tlv[tlvlen++] = 0xFE;
    printf("NDEF TLV: %d bytes (\"%s\")\n", tlvlen, payload);

    int i2cfd, irqfd;
    if(prep(&i2cfd, &irqfd) < 0) return 1;
    if(nci_full_init(i2cfd, irqfd) < 0) return 3;
    if(!rf_discover_wait(i2cfd, irqfd)){
        rf_deactivate(i2cfd, irqfd);
        printf("RESULT: no tag detected.\n"); return 4;
    }

    if(g_rf_proto != 0x02){
        printf("RESULT: ndef-write currently supports Type 2 (NTAG/Ultralight) "
               "only -- got RF proto 0x%02x.\n", g_rf_proto);
        rf_deactivate(i2cfd, irqfd);
        return 5;
    }

    /* Sanity-check the CC: must be NDEF-formatted, writable, big enough. */
    uint8_t cc[16];
    if(t2t_read(i2cfd, irqfd, 3, cc) < 0){
        printf("RESULT: cannot read CC at block 3.\n");
        rf_deactivate(i2cfd, irqfd); return 6;
    }
    if(cc[0] != 0xE1){
        printf("RESULT: tag not NDEF-formatted (CC magic 0x%02x != 0xE1).\n", cc[0]);
        rf_deactivate(i2cfd, irqfd); return 6;
    }
    int total = cc[2] * 8;
    if((cc[3] >> 4) != 0){
        printf("RESULT: tag is read-only (CC access bits 0x%02x).\n", cc[3]);
        rf_deactivate(i2cfd, irqfd); return 6;
    }
    if(tlvlen > total){
        printf("RESULT: NDEF (%d bytes) larger than tag user memory (%d).\n",
               tlvlen, total);
        rf_deactivate(i2cfd, irqfd); return 6;
    }

    /* Write TLV starting at block 4 in 4-byte chunks. */
    int blocks = (tlvlen + 3) / 4;
    printf("Writing %d bytes (%d blocks, blocks 4..%d)...\n",
           tlvlen, blocks, 3 + blocks);
    for(int b = 0; b < blocks; b++){
        uint8_t four[4] = {0,0,0,0};
        int copy = tlvlen - b * 4; if(copy > 4) copy = 4;
        memcpy(four, tlv + b * 4, copy);
        if(t2t_write_block(i2cfd, irqfd, 4 + b, four) < 0){
            printf("RESULT: write failed at block %d.\n", 4 + b);
            rf_deactivate(i2cfd, irqfd); return 6;
        }
    }

    /* Verify by reading user memory back. */
    printf("-- verify --\n");
    uint8_t mem[256]; int access;
    int mlen = t2t_load_user_memory(i2cfd, irqfd, mem, sizeof mem, &access);
    rf_deactivate(i2cfd, irqfd);
    if(mlen < tlvlen){
        printf("RESULT: write completed but read-back too short.\n"); return 7;
    }
    if(memcmp(mem, tlv, tlvlen) != 0){
        printf("RESULT: read-back differs from what was written.\n"); return 7;
    }
    printf("RESULT: NDEF written and verified.\n");
    return 0;
}

/* ---- Programmable HCE (emulate-apdu) ---------------------------------- */

#define APDU_MAX_RULES 32
struct apdu_rule {
    uint8_t  pat[64]; int plen;
    int      prefix;            /* 1 = pattern matches as a prefix */
    uint8_t  resp[260]; int rlen;
};
static struct apdu_rule g_rules[APDU_MAX_RULES];
static int g_n_rules;

#define HEX_NIBBLE(c) (((c)>='0'&&(c)<='9') ? (c)-'0' : \
                       ((c)>='a'&&(c)<='f') ? (c)-'a'+10 : \
                       ((c)>='A'&&(c)<='F') ? (c)-'A'+10 : -1)

/* Parse space-tolerant hex bytes, optionally with a trailing '*'. */
static int parse_hex_field(const char *s, uint8_t *out, int maxlen, int *prefix_out){
    int n = 0; *prefix_out = 0;
    while(*s){
        while(*s == ' ' || *s == '\t') s++;
        if(*s == 0) break;
        if(*s == '*'){
            *prefix_out = 1; s++;
            while(*s == ' ' || *s == '\t') s++;
            if(*s) return -1;
            break;
        }
        int hi = HEX_NIBBLE(s[0]);
        int lo = HEX_NIBBLE(s[1]);
        if(hi < 0 || lo < 0) return -1;
        if(n >= maxlen) return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
        s += 2;
    }
    return n;
}

static int load_apdu_conf(const char *path){
    FILE *f = fopen(path, "r");
    if(!f){
        fprintf(stderr,"cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    char line[512]; int lineno = 0; g_n_rules = 0;
    while(fgets(line, sizeof line, f) && g_n_rules < APDU_MAX_RULES){
        lineno++;
        char *p = line;
        while(*p == ' ' || *p == '\t') p++;
        if(*p == '#' || *p == '\n' || *p == 0 || *p == '\r') continue;
        char *colon = strchr(p, ':');
        if(!colon){
            fprintf(stderr,"line %d: missing ':'\n", lineno); continue;
        }
        *colon = 0;
        char *right = colon + 1;
        char *end = right + strlen(right);
        while(end > right && (end[-1]=='\n' || end[-1]=='\r' ||
                              end[-1]==' '  || end[-1]=='\t')) *--end = 0;

        struct apdu_rule *r = &g_rules[g_n_rules];
        int plen = parse_hex_field(p, r->pat, sizeof r->pat, &r->prefix);
        if(plen < 0){
            fprintf(stderr,"line %d: bad pattern\n", lineno); continue;
        }
        r->plen = plen;
        int dummy;
        int rlen = parse_hex_field(right, r->resp, sizeof r->resp, &dummy);
        if(rlen < 2 || dummy){
            fprintf(stderr,"line %d: bad/short response (need >=2 bytes incl SW)\n",
                    lineno);
            continue;
        }
        r->rlen = rlen;
        g_n_rules++;
    }
    fclose(f);
    return g_n_rules;
}

static int match_apdu_rule(const uint8_t *a, int alen, uint8_t *resp, int *rlen){
    for(int i = 0; i < g_n_rules; i++){
        struct apdu_rule *r = &g_rules[i];
        if(r->plen > alen) continue;
        if(r->plen && memcmp(a, r->pat, r->plen) != 0) continue;
        if(!r->prefix && r->plen != alen) continue;
        memcpy(resp, r->resp, r->rlen); *rlen = r->rlen;
        return i;
    }
    resp[0] = 0x6A; resp[1] = 0x82; *rlen = 2;
    return -1;
}

static int do_emulate_apdu(int argc, char **argv){
    if(argc < 1){
        fprintf(stderr,
            "usage: stnfc emulate-apdu <conf-file>\n"
            "  config syntax (one rule per line):\n"
            "    HEX_PATTERN [*] : HEX_RESPONSE\n"
            "  examples:\n"
            "    # SELECT AID F00102030405 -> OK\n"
            "    00 A4 04 00 07 F0 01 02 03 04 05 06 : 90 00\n"
            "    # READ BINARY (any P1 P2 Le) -> 'TEST' + OK\n"
            "    00 B0 * : 54 45 53 54 90 00\n"
            "    # catch-all -> not found\n"
            "    * : 6A 82\n");
        return 1;
    }
    if(load_apdu_conf(argv[0]) <= 0){
        fprintf(stderr,"no rules loaded\n"); return 1;
    }
    printf("Loaded %d APDU rule(s) from %s\n", g_n_rules, argv[0]);

    int i2cfd, irqfd;
    if(prep(&i2cfd, &irqfd) < 0) return 1;
    if(nci_chip_init(i2cfd, irqfd) < 0) return 3;

    nci_cmd(i2cfd, irqfd, "RF_DISCOVER_MAP (ISO-DEP listen)",
            rfmap_listen_iso, sizeof rfmap_listen_iso, 200);
    uint8_t disc[] = { 0x21, 0x03, 0x03,  0x01,  0x80, 0x01 };
    nci_cmd(i2cfd, irqfd, "RF_DISCOVER (NFC-A passive listen)",
            disc, sizeof disc, 200);

    int deadline = g_timeout < 5000 ? 30000 : g_timeout;
    printf("\n*** Programmable HCE active (%d rules) ***\n", g_n_rules);
    printf("    Tap a reader. Window: %d ms. Ctrl+C to stop early.\n\n",
           deadline);

    signal(SIGINT, on_sigint);
    int activated = 0, taps = 0, apdus = 0, elapsed = 0;
    uint8_t buf[300], resp[300];

    while(!g_stop && elapsed < deadline){
        int n = nci_read(i2cfd, irqfd, buf, 500);
        if(n == -2){ elapsed += 500; continue; }
        if(n < 0)   { elapsed += 50;  continue; }
        nci_decode(buf, n);

        if(buf[0] == 0x61 && buf[1] == 0x05){
            activated = 1; taps++;
            printf("\n--- reader tap #%d ---\n", taps);
        } else if(buf[0] == 0x61 && buf[1] == 0x06){
            if(activated){ printf("--- reader left ---\n\n"); activated = 0; }
        } else if((buf[0] & 0xE0) == 0x00 && n >= 3 && activated){
            int alen = buf[2];
            int rlen, ridx = match_apdu_rule(buf + 3, alen, resp, &rlen);
            printf("  <- APDU(%d):", alen);
            for(int j = 0; j < alen && j < 32; j++) printf(" %02x", buf[3 + j]);
            if(alen > 32) printf(" ...");
            printf("\n  -> %s(%d):", ridx >= 0 ? "rule" : "default", rlen);
            for(int j = 0; j < rlen && j < 32; j++) printf(" %02x", resp[j]);
            if(rlen > 32) printf(" ...");
            printf("\n");

            uint8_t pkt[3 + 260];
            pkt[0] = 0x00; pkt[1] = 0x00; pkt[2] = (uint8_t)rlen;
            memcpy(pkt + 3, resp, rlen);
            nci_write(i2cfd, pkt, 3 + rlen);
            apdus++;
        }
    }

    printf("\nstopping... (%d tap(s), %d APDU(s) handled)\n", taps, apdus);
    rf_deactivate(i2cfd, irqfd);
    return apdus > 0 ? 0 : 4;
}

/* ---- clone: scan a tag, emit a replayable emulator config ------------- */

static FILE *g_clone_out;

static void clone_hdr(const char *src){
    fprintf(g_clone_out,
        "# Cloned from %s (by `stnfc clone`).\n"
        "# Replay with `stnfc emulate-apdu <this-file>`.\n\n", src);
}

/* Write a complete Type 4 NDEF emulator rule set carrying `ndef`/`nlen`. */
static void clone_emit_ndef_rules(const uint8_t *ndef, int nlen){
    fprintf(g_clone_out, "# SELECT NDEF tag application AID\n");
    fprintf(g_clone_out, "00 A4 04 00 07 D2 76 00 00 85 01 01 * : 90 00\n\n");
    fprintf(g_clone_out, "# SELECT CC file E1 03\n");
    fprintf(g_clone_out, "00 A4 00 0C 02 E1 03 * : 90 00\n\n");
    fprintf(g_clone_out, "# SELECT NDEF file E1 04\n");
    fprintf(g_clone_out, "00 A4 00 0C 02 E1 04 * : 90 00\n\n");
    fprintf(g_clone_out, "# READ CC (15 bytes)\n");
    fprintf(g_clone_out,
        "00 B0 00 00 0F : 00 0F 20 00 7F 00 7F 04 06 E1 04 0F FE 00 FF 90 00\n\n");
    fprintf(g_clone_out, "# READ NLEN (2 bytes, %d)\n", nlen);
    fprintf(g_clone_out, "00 B0 00 00 02 : %02X %02X 90 00\n\n",
            (nlen >> 8) & 0xFF, nlen & 0xFF);
    fprintf(g_clone_out, "# READ NDEF message data (offset 2, any Le)\n");
    fprintf(g_clone_out, "00 B0 00 02 * :");
    for(int i = 0; i < nlen; i++) fprintf(g_clone_out, " %02X", ndef[i]);
    fprintf(g_clone_out, " 90 00\n\n");
    fprintf(g_clone_out, "# Catch-all\n* : 6A 82\n");
}

static int clone_t2t(int i2cfd, int irqfd){
    uint8_t mem[256]; int access;
    int mlen = t2t_load_user_memory(i2cfd, irqfd, mem, sizeof mem, &access);
    if(mlen <= 0){ fprintf(stderr,"  T2T: user-memory read failed\n"); return -1; }
    int off, nlen;
    if(ndef_find_tlv(mem, mlen, &off, &nlen) < 0){
        fprintf(stderr,"  T2T: no NDEF TLV in user memory\n"); return -1;
    }
    printf("  captured Type 2 NDEF: %d bytes\n", nlen);
    clone_hdr("Type 2 / NTAG / Ultralight NDEF tag");
    clone_emit_ndef_rules(mem + off, nlen);
    return 0;
}

/* Probe a known set of APDUs on a generic ISO-DEP card; capture responses. */
struct probe { const char *name; const uint8_t *apdu; int alen; };
static const uint8_t p_pse[]  = {0x00,0xA4,0x04,0x00,0x0E,
    0x31,0x50,0x41,0x59,0x2E,0x53,0x59,0x53,0x2E,0x44,0x44,0x46,0x30,0x31,0x00};
static const uint8_t p_ppse[] = {0x00,0xA4,0x04,0x00,0x0E,
    0x32,0x50,0x41,0x59,0x2E,0x53,0x59,0x53,0x2E,0x44,0x44,0x46,0x30,0x31,0x00};
static const uint8_t p_gd[]   = {0x00,0xCA,0x00,0x00,0x00};
static const uint8_t p_des[]  = {0x90,0x60,0x00,0x00,0x00};

static int clone_t4(int i2cfd, int irqfd){
    uint8_t rx[300]; int rxlen;
    static const uint8_t s_aid[] = {
        0x00,0xA4,0x04,0x00,0x07,0xD2,0x76,0x00,0x00,0x85,0x01,0x01,0x00
    };
    if(t4t_send_apdu(i2cfd, irqfd, s_aid, sizeof s_aid, rx, &rxlen) == 0){
        /* NDEF tag application present -- fall through to standard Type 4 read. */
        static const uint8_t s_cc[] = {0x00,0xA4,0x00,0x0C,0x02,0xE1,0x03};
        if(t4t_send_apdu(i2cfd, irqfd, s_cc, sizeof s_cc, rx, &rxlen) < 0) return -1;
        static const uint8_t r_cc[] = {0x00,0xB0,0x00,0x00,0x0F};
        if(t4t_send_apdu(i2cfd, irqfd, r_cc, sizeof r_cc, rx, &rxlen) < 0
           || rxlen < 11) return -1;
        uint16_t ndef_id = (rx[9] << 8) | rx[10];
        uint8_t s_nd[] = {0x00,0xA4,0x00,0x0C,0x02,
                          (uint8_t)(ndef_id >> 8), (uint8_t)ndef_id};
        if(t4t_send_apdu(i2cfd, irqfd, s_nd, sizeof s_nd, rx, &rxlen) < 0) return -1;
        static const uint8_t r_nl[] = {0x00,0xB0,0x00,0x00,0x02};
        if(t4t_send_apdu(i2cfd, irqfd, r_nl, sizeof r_nl, rx, &rxlen) < 0
           || rxlen < 2) return -1;
        int nlen = (rx[0] << 8) | rx[1];
        uint8_t msg[1024]; int got = 0;
        while(got < nlen){
            int want = nlen - got; if(want > 0x7F) want = 0x7F;
            uint8_t r_md[] = {0x00,0xB0,
                              (uint8_t)((2+got) >> 8), (uint8_t)(2+got),
                              (uint8_t)want};
            if(t4t_send_apdu(i2cfd, irqfd, r_md, sizeof r_md, rx, &rxlen) < 0
               || rxlen < want) return -1;
            memcpy(msg + got, rx, want); got += want;
        }
        printf("  captured Type 4 NDEF: %d bytes\n", nlen);
        clone_hdr("Type 4 / ISO-DEP NDEF tag");
        clone_emit_ndef_rules(msg, nlen);
        return 0;
    }

    printf("  ISO-DEP card with no NDEF application -- probing public APDUs\n");
    clone_hdr("Generic ISO-DEP card (probe-based clone -- public APDUs only)");
    static const struct probe probes[] = {
        {"PSE (EMV)",       p_pse,  sizeof p_pse},
        {"PPSE (EMV-CL)",   p_ppse, sizeof p_ppse},
        {"GET DATA",        p_gd,   sizeof p_gd},
        {"DESFire GetVer",  p_des,  sizeof p_des},
    };
    int captured = 0;
    for(unsigned i = 0; i < sizeof probes/sizeof probes[0]; i++){
        uint8_t r[300]; int rl;
        if(t4t_send_apdu_raw(i2cfd, irqfd, probes[i].apdu, probes[i].alen,
                             r, &rl) < 0){
            printf("  %s : link torn down, re-activating\n", probes[i].name);
            if(!rf_discover_wait(i2cfd, irqfd)) break;
            continue;
        }
        printf("  %s -> %d-byte response, SW=%02X%02X\n",
               probes[i].name, rl, r[rl-2], r[rl-1]);
        fprintf(g_clone_out, "# %s response\n", probes[i].name);
        for(int j = 0; j < probes[i].alen; j++)
            fprintf(g_clone_out, "%02X ", probes[i].apdu[j]);
        fprintf(g_clone_out, ":");
        for(int j = 0; j < rl; j++) fprintf(g_clone_out, " %02X", r[j]);
        fprintf(g_clone_out, "\n\n");
        captured++;
    }
    fprintf(g_clone_out, "# Catch-all -- unrecognized APDUs get 6A82\n");
    fprintf(g_clone_out, "* : 6A 82\n");
    return captured > 0 ? 0 : -1;
}

/* MIFARE Classic: dump for reference; chip can't emulate this protocol. */
static int clone_mfc(int i2cfd, int irqfd){
    printf("  WARNING: ST21NFC CLF cannot emulate MIFARE Classic in listen mode.\n");
    printf("  Dumping the tag's content for reference (not for emulation).\n");
    fprintf(g_clone_out,
        "# MIFARE Classic 1K dump.\n"
        "# NOTE: this is NOT an emulator config -- the ST21NFC chip in the\n"
        "# Pixel 4a does not support MIFARE Classic listen-mode emulation.\n"
        "# This dump is for reference / cloning to another blank MIFARE 1K\n"
        "# (would need a separate `mfc-write-all` tool, destructive).\n\n");
    fprintf(g_clone_out, "# UID:");
    for(int i = 0; i < g_uidlen; i++) fprintf(g_clone_out, " %02X", g_uid[i]);
    fprintf(g_clone_out, "  SAK: %02X\n\n", g_sak);

    int dumped = 0;
    for(int s = 0; s < 16; s++){
        if(mfc_auth(i2cfd, irqfd, s * 4) < 0){
            fprintf(g_clone_out, "# sector %d: AUTH FAILED (key A != FF*6)\n", s);
            if(!rf_discover_wait(i2cfd, irqfd)) break;
            continue;
        }
        for(int b = s*4; b < s*4 + 4; b++){
            uint8_t pkt[] = {0x00,0x00,0x02,0x30,(uint8_t)b};
            uint8_t rx[300]; int rxlen, deact;
            data_xfer(i2cfd, irqfd, pkt, 5, rx, &rxlen, &deact);
            if(rxlen >= 16){
                fprintf(g_clone_out, "# block %2d:", b);
                for(int k = 0; k < 16; k++) fprintf(g_clone_out, " %02X", rx[k]);
                fprintf(g_clone_out, "\n");
                dumped++;
            }
            if(deact) break;
        }
    }
    fprintf(g_clone_out, "\n# %d/64 blocks captured.\n", dumped);
    return dumped > 0 ? 0 : -1;
}

static int do_clone(int argc, char **argv){
    if(argc < 1){
        fprintf(stderr,"usage: stnfc clone <output-file>\n");
        return 1;
    }
    g_clone_out = fopen(argv[0], "w");
    if(!g_clone_out){
        fprintf(stderr,"cannot open %s: %s\n", argv[0], strerror(errno));
        return 1;
    }

    int i2cfd, irqfd;
    if(prep(&i2cfd, &irqfd) < 0){ fclose(g_clone_out); return 1; }
    if(nci_full_init(i2cfd, irqfd) < 0){ fclose(g_clone_out); return 3; }
    if(!rf_discover_wait(i2cfd, irqfd)){
        rf_deactivate(i2cfd, irqfd); fclose(g_clone_out);
        printf("RESULT: no tag detected.\n"); return 4;
    }

    int r = -1;
    if(g_rf_proto == 0x02){
        printf("\n-- cloning Type 2 (NTAG/Ultralight) --\n");
        r = clone_t2t(i2cfd, irqfd);
    } else if(g_rf_proto == 0x04){
        printf("\n-- cloning Type 4 / ISO-DEP --\n");
        r = clone_t4(i2cfd, irqfd);
    } else if(g_rf_proto == 0x90 || g_sak == 0x08){
        printf("\n-- cloning MIFARE Classic (dump only) --\n");
        r = clone_mfc(i2cfd, irqfd);
    } else {
        printf("\n-- RF protocol 0x%02x: clone path not implemented --\n",
               g_rf_proto);
    }

    rf_deactivate(i2cfd, irqfd);
    fclose(g_clone_out);
    if(r == 0){
        printf("\nRESULT: clone saved to %s\n", argv[0]);
        if(g_rf_proto != 0x90 && g_sak != 0x08)
            printf("        replay with:  stnfc emulate-apdu %s\n", argv[0]);
        return 0;
    }
    printf("\nRESULT: clone failed.\n");
    return 6;
}

/* ---- mfc-keys: dictionary attack against the current tag's sectors --- */

static const uint8_t mfc_default_keys[][6] = {
    {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}, /* factory default */
    {0x00,0x00,0x00,0x00,0x00,0x00}, /* blank */
    {0xA0,0xA1,0xA2,0xA3,0xA4,0xA5}, /* NDEF MAD public key */
    {0xD3,0xF7,0xD3,0xF7,0xD3,0xF7}, /* NDEF data key A */
    {0xB0,0xB1,0xB2,0xB3,0xB4,0xB5}, /* transit / common */
    {0x4D,0x3A,0x99,0xC3,0x51,0xDD}, /* hotel-card variant */
    {0x1A,0x98,0x2C,0x7E,0x45,0x9A}, /* transport variant */
    {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF}, /* very common test */
    {0x14,0x28,0x32,0x14,0x28,0x32}, /* common */
    {0x56,0x33,0x7B,0x9C,0x86,0x87}, /* common */
    {0x6B,0xBE,0xE6,0x46,0xEB,0x0E}, /* transit */
    {0x71,0xF3,0xA3,0x15,0xAD,0x26}, /* transit */
    {0xF1,0xD8,0x3F,0x96,0x4D,0xE3}, /* hotel */
    {0x44,0x4D,0x49,0x46,0x41,0x52}, /* "DMIFAR" ASCII */
};
#define MFC_N_DEFAULT_KEYS \
    ((int)(sizeof mfc_default_keys / sizeof mfc_default_keys[0]))

static int do_keys(int argc, char **argv){
    (void)argc; (void)argv;

    int i2cfd, irqfd;
    if(prep(&i2cfd, &irqfd) < 0) return 1;
    if(nci_full_init(i2cfd, irqfd) < 0) return 3;
    if(!rf_discover_wait(i2cfd, irqfd)){
        rf_deactivate(i2cfd, irqfd);
        printf("RESULT: no tag detected.\n"); return 4;
    }
    if(g_sak != 0x08){
        printf("RESULT: SAK 0x%02x is not MIFARE Classic 1K.\n", g_sak);
        rf_deactivate(i2cfd, irqfd); return 5;
    }
    printf("Trying %d built-in default keys against 16 sectors...\n\n",
           MFC_N_DEFAULT_KEYS);

    int sectors_open = 0;
    for(int s = 0; s < 16; s++){
        int hit = -1;
        for(int k = 0; k < MFC_N_DEFAULT_KEYS; k++){
            if(mfc_auth_with_key(i2cfd, irqfd, s * 4,
                                  mfc_default_keys[k], /*verbose*/0) == 0){
                hit = k; break;
            }
            /* Failed auth tears down the RF link -- re-activate. */
            if(!rf_discover_wait(i2cfd, irqfd)){ hit = -2; break; }
        }
        if(hit >= 0){
            printf("  sector %2d : key A = ", s);
            for(int i = 0; i < 6; i++)
                printf("%02X ", mfc_default_keys[hit][i]);
            printf(" (dict entry %d)\n", hit);
            sectors_open++;
        } else if(hit == -2){
            printf("  sector %2d : no re-activation; aborting\n", s);
            break;
        } else {
            printf("  sector %2d : NO MATCH in built-in dictionary\n", s);
        }
    }
    rf_deactivate(i2cfd, irqfd);
    printf("\nRESULT: opened %d/16 sectors with built-in dictionary.\n",
           sectors_open);
    if(sectors_open < 16){
        printf("        (sectors with custom keys need a real dictionary file --\n"
               "         feed common-key DBs from MFOC / mfcuk-like tools).\n");
    }
    return sectors_open > 0 ? 0 : 6;
}

/* ---- mfc-copy: write a MIFARE Classic 1K dump to the current tag ----- */

/* Parse a "# block NN: HH HH ... HH" line. Returns block number, -1 if no
 * match; writes 16 bytes into `out` on a match. */
static int parse_mfc_dump_line(const char *line, uint8_t *out){
    const char *p = line;
    while(*p == ' ' || *p == '\t') p++;
    if(*p != '#') return -1;
    p++;
    while(*p == ' ' || *p == '\t') p++;
    if(strncmp(p, "block", 5) != 0) return -1;
    p += 5;
    while(*p == ' ' || *p == '\t') p++;
    char *end;
    long blk = strtol(p, &end, 10);
    if(end == p || *end != ':') return -1;
    p = end + 1;
    int n = 0;
    while(*p && n < 16){
        while(*p == ' ' || *p == '\t') p++;
        if(*p == '\n' || *p == '\r' || *p == 0) break;
        int hi = HEX_NIBBLE(p[0]);
        int lo = HEX_NIBBLE(p[1]);
        if(hi < 0 || lo < 0) return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
        p += 2;
    }
    if(n != 16) return -1;
    return (int)blk;
}

static int do_mfc_copy(int argc, char **argv){
    int write_trailers = 0, i;
    for(i = 0; i < argc; i++){
        if(strcmp(argv[i], "--write-trailers") == 0) write_trailers = 1;
        else break;
    }
    if(i >= argc){
        fprintf(stderr,
            "usage: stnfc mfc-copy [--write-trailers] <dump-file>\n"
            "  Writes a MIFARE Classic 1K dump (from `stnfc clone`) to\n"
            "  the tag currently on the phone. Block 0 (UID) is always\n"
            "  skipped (read-only on standard MIFARE Classic). Sector\n"
            "  trailers (blocks 3,7,11,...) are skipped unless\n"
            "  --write-trailers is given -- bad trailer writes can\n"
            "  permanently lock the sector.\n");
        return 1;
    }
    const char *path = argv[i];
    FILE *f = fopen(path, "r");
    if(!f){
        fprintf(stderr,"cannot open %s: %s\n", path, strerror(errno));
        return 1;
    }
    uint8_t blocks[64][16];
    int have[64] = {0};
    char line[512];
    while(fgets(line, sizeof line, f)){
        uint8_t buf[16];
        int blk = parse_mfc_dump_line(line, buf);
        if(blk >= 0 && blk < 64){
            memcpy(blocks[blk], buf, 16);
            have[blk] = 1;
        }
    }
    fclose(f);
    int loaded = 0;
    for(int b = 0; b < 64; b++) if(have[b]) loaded++;
    printf("Loaded %d/64 blocks from %s\n", loaded, path);
    if(loaded == 0){
        fprintf(stderr,"no '# block N: ...' lines parsed from dump\n");
        return 1;
    }

    int i2cfd, irqfd;
    if(prep(&i2cfd, &irqfd) < 0) return 1;
    if(nci_full_init(i2cfd, irqfd) < 0) return 3;
    if(!rf_discover_wait(i2cfd, irqfd)){
        rf_deactivate(i2cfd, irqfd);
        printf("RESULT: no destination tag detected.\n"); return 4;
    }
    if(g_sak != 0x08){
        printf("RESULT: destination is not MIFARE Classic 1K (SAK 0x%02x).\n",
               g_sak);
        rf_deactivate(i2cfd, irqfd); return 5;
    }
    printf("Destination UID:");
    for(int j = 0; j < g_uidlen; j++) printf(" %02x", g_uid[j]);
    printf("  SAK 0x%02x\n\n", g_sak);

    int written = 0, skipped = 0, failed = 0;
    int cur_sector = -1;
    for(int b = 0; b < 64; b++){
        if(!have[b]){ continue; }
        if(b == 0){
            printf("  block  0 : skip (manufacturer/UID, read-only)\n");
            skipped++; continue;
        }
        if((b % 4) == 3 && !write_trailers){
            printf("  block %2d : skip (sector trailer; use --write-trailers to force)\n", b);
            skipped++; continue;
        }
        if(b / 4 != cur_sector){
            if(mfc_auth(i2cfd, irqfd, (b / 4) * 4) < 0){
                printf("  sector %d : auth FAILED -- destination uses non-default keys\n",
                       b / 4);
                int s = b / 4;
                while(b < 64 && b / 4 == s){ failed++; b++; }
                b--;
                if(!rf_discover_wait(i2cfd, irqfd)) break;
                cur_sector = -1;
                continue;
            }
            cur_sector = b / 4;
        }
        if(mfc_write(i2cfd, irqfd, b, blocks[b]) < 0){
            failed++; continue;
        }
        uint8_t verif[16];
        if(mfc_read(i2cfd, irqfd, b, verif) != 0 ||
           memcmp(verif, blocks[b], 16) != 0){
            printf("  block %2d : VERIFY FAILED\n", b);
            failed++; continue;
        }
        written++;
    }
    rf_deactivate(i2cfd, irqfd);
    printf("\nRESULT: wrote %d block(s), skipped %d (block 0 / trailers / "
           "missing-from-dump), failed %d.\n", written, skipped, failed);
    return written > 0 ? 0 : 6;
}

static int do_raw(int argc,char **argv){
    uint8_t cmd[260]; int len=0;
    for(int i=0;i<argc && len<260;i++) cmd[len++]=(uint8_t)strtol(argv[i],0,16);
    if(len<3){ fprintf(stderr,"raw: need at least 3 bytes (NCI header)\n"); return 1; }
    int i2cfd,irqfd;
    if(prep(&i2cfd,&irqfd)<0) return 1;
    nci_drain(i2cfd,irqfd,300,80);          /* clear post-reset chatter */
    hexdump(">>",cmd,len);
    if(nci_write(i2cfd,cmd,len)<0) return 2;
    int n=nci_drain(i2cfd,irqfd,g_timeout,150);
    printf("%d reply packet(s).\n",n);
    return 0;
}

/* ---- main -------------------------------------------------------------- */
int main(int argc,char **argv){
    int i=1;
    for(;i<argc && argv[i][0]=='-';i++){
        if(!strcmp(argv[i],"--bus")&&i+1<argc)        g_bus=argv[++i];
        else if(!strcmp(argv[i],"--addr")&&i+1<argc)  g_addr=strtol(argv[++i],0,16);
        else if(!strcmp(argv[i],"--chip")&&i+1<argc)  g_chip=atoi(argv[++i]);
        else if(!strcmp(argv[i],"--rst")&&i+1<argc)   g_rst=atoi(argv[++i]);
        else if(!strcmp(argv[i],"--irq")&&i+1<argc)   g_irq=atoi(argv[++i]);
        else if(!strcmp(argv[i],"--timeout")&&i+1<argc) g_timeout=atoi(argv[++i]);
        else if(!strcmp(argv[i],"--inv-reset"))       g_inv_reset=1;
        else if(!strcmp(argv[i],"--inv-irq"))         g_inv_irq=1;
        else if(!strcmp(argv[i],"--no-reset"))        g_no_reset=1;
        else if(!strcmp(argv[i],"--la-nfcid1") && i+1<argc){
            /* Parse hex bytes (space, colon, or contiguous). */
            const char *s = argv[++i];
            g_la_nfcid1_len = 0;
            while(*s && g_la_nfcid1_len < 10){
                while(*s == ' ' || *s == ':' || *s == '\t') s++;
                if(!*s) break;
                int hi = HEX_NIBBLE(s[0]);
                int lo = (s[1] ? HEX_NIBBLE(s[1]) : -1);
                if(hi < 0 || lo < 0){
                    fprintf(stderr,"bad hex in --la-nfcid1\n"); return 1;
                }
                g_la_nfcid1[g_la_nfcid1_len++] = (uint8_t)((hi<<4)|lo);
                s += 2;
            }
            if(g_la_nfcid1_len != 4 && g_la_nfcid1_len != 7 && g_la_nfcid1_len != 10){
                fprintf(stderr,"--la-nfcid1 needs 4, 7, or 10 bytes (got %d)\n",
                        g_la_nfcid1_len);
                return 1;
            }
        }
        else { fprintf(stderr,"unknown flag %s\n",argv[i]); return 1; }
    }
    if(i>=argc){
        fprintf(stderr,"usage: stnfc [flags] info|reset|nci|poll|read|write|dump|keys|apdu|ndef-read|ndef-write|emulate-ndef|emulate-wifi|emulate-vcard|emulate-apdu|clone|mfc-copy|drain|raw HH..\n");
        return 1;
    }
    const char *cmd=argv[i++];
    if(!strcmp(cmd,"info"))  return do_info();
    if(!strcmp(cmd,"reset")) return do_reset();
    if(!strcmp(cmd,"nci"))   return do_nci();
    if(!strcmp(cmd,"poll"))  return do_poll();
    if(!strcmp(cmd,"read"))  return do_read(argc-i,argv+i);
    if(!strcmp(cmd,"write")) return do_write(argc-i,argv+i);
    if(!strcmp(cmd,"dump"))  return do_dump();
    if(!strcmp(cmd,"keys"))  return do_keys(argc-i,argv+i);
    if(!strcmp(cmd,"apdu"))  return do_apdu(argc-i,argv+i);
    if(!strcmp(cmd,"ndef-read"))    return do_ndef_read();
    if(!strcmp(cmd,"ndef-write"))   return do_ndef_write(argc-i,argv+i);
    if(!strcmp(cmd,"emulate-ndef"))  return do_emulate_ndef(argc-i,argv+i);
    if(!strcmp(cmd,"emulate-wifi"))  return do_emulate_wifi(argc-i,argv+i);
    if(!strcmp(cmd,"emulate-vcard")) return do_emulate_vcard(argc-i,argv+i);
    if(!strcmp(cmd,"emulate-apdu"))  return do_emulate_apdu(argc-i,argv+i);
    if(!strcmp(cmd,"clone"))        return do_clone(argc-i,argv+i);
    if(!strcmp(cmd,"mfc-copy"))     return do_mfc_copy(argc-i,argv+i);
    if(!strcmp(cmd,"drain")) return do_drain();
    if(!strcmp(cmd,"raw"))   return do_raw(argc-i,argv+i);
    fprintf(stderr,"unknown subcommand %s\n",cmd);
    return 1;
}
