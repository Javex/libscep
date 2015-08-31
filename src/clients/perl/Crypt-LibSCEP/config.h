typedef struct {
char *passin;
char *passwd;
BIO *log;
ENGINE *engine;
} Conf;

typedef struct {
char *so;
char *pin;
char *label;
char *module;
ENGINE *engine;
} Engine_conf;