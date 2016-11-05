

TARGETNAME ?= frontend.exe


to_lowercase = $(subst A,a,$(subst B,b,$(subst C,c,$(subst D,d,$(subst E,e,$(subst F,f,$(subst G,g,$(subst H,h,$(subst I,i,$(subst J,j,$(subst K,k,$(subst L,l,$(subst M,m,$(subst N,n,$(subst O,o,$(subst P,p,$(subst Q,q,$(subst R,r,$(subst S,s,$(subst T,t,$(subst U,u,$(subst V,v,$(subst W,w,$(subst X,x,$(subst Y,y,$(subst Z,z,$1))))))))))))))))))))))))))
rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) $(filter $(subst *,%,$2),$d))

CONFIG ?= RELEASE


CONFIGURATION_FLAGS_FILE := $(call to_lowercase,$(CONFIG)).mak
include $(CONFIGURATION_FLAGS_FILE)


ifeq ($(BINARYDIR),)
error:
	$(error Invalid configuration, please check your inputs)
endif


PRIMARY_LIB=$(BINARYDIR)/libOTe.a 
PRIMARYTESTS_LIB=$(BINARYDIR)/libOTeTests.a

SOLUTION_DIR = $(shell pwd)
PREPROCESSOR_MACROS += SOLUTION_DIR=\"$(SOLUTION_DIR)\"

SRC= .

FRONTEND_DIR=$(SRC)/frontend
PRIMARY_DIR=$(SRC)/libOTe/
PRIMARYTESTS_DIR=$(SRC)/libOTe_Tests


FRONTEND_SRC=$(wildcard $(FRONTEND_DIR)/*.cpp)
FRONTEND_OBJ=$(addprefix $(BINARYDIR)/,$(FRONTEND_SRC:.cpp=.o))


PRIMARY_SRC=\
	$(call rwildcard, $(PRIMARY_DIR), *.cpp)

PRIMARY_SRC_C=\
	$(call rwildcard, $(PRIMARY_DIR), *.c)


PRIMARY_ASM=\
	$(call rwildcard, $(PRIMARY_DIR), *.S)



PRIMARY_OBJ=\
	$(addprefix $(BINARYDIR)/,$(PRIMARY_SRC:.cpp=.o)) \
	$(addprefix $(BINARYDIR)/,$(PRIMARY_SRC_C:.c=.o)) \
	$(addprefix $(BINARYDIR)/,$(PRIMARY_ASM:.S=.asm.o)) 

#PRIMARY_H=\
#	$(PRIMARY_SRC:.cpp=.h)\
#	$(PRIMARY_SRC_C:.c=.h)

PRIMARYTESTS_SRC=$(wildcard $(PRIMARYTESTS_DIR)/*.cpp) 
PRIMARYTESTS_OBJ=$(addprefix $(BINARYDIR)/,$(PRIMARYTESTS_SRC:.cpp=.o))
PRIMARYTESTS_H=$(PRIMARYTESTS_SRC:.cpp=.h)

NASMFLAGS?=-f elf64 
NASM?=nasm

TPL=thirdparty/linux
BOOST=thirdparty/linux/boost


INC=-I./libOTe/\
	-I./libOTe_Tests/\
	-I$(TPL)\
	-I$(BOOST)/includes/

TPL_LIB=$(BOOST)/stage/lib/libboost_system.a\
	$(BOOST)/stage/lib/libboost_thread.a\
	$(TPL)/miracl/miracl/source/libmiracl.a\
	$(TPL)/cryptopp/libcryptopp.a

LIB=\
	$(TPL_LIB)\
	-lpthread\
	-lrt

#EXPORTHEADS=$(PRIMARY_H) $(PRIMARYTESTS_H)


LDFLAGS += $(COMMONFLAGS)
LDFLAGS += -L$(BINARYDIR)
LDFLAGS += $(addprefix -L,$(LIBRARY_DIRS))
#LDFLAGS += $(addprefix -l,$(LIBRARY_NAMES))

#LDFLAGS +=  -Wl,--verbose

CXXFLAGS += $(COMMONFLAGS)
CXXFLAGS += $(addprefix -I,$(INCLUDE_DIRS)) -std=c++11 
CXXFLAGS += $(addprefix -D,$(PREPROCESSOR_MACROS))





#######################################################################################


PRIMARY_OUTPUTS := \
	$(BINARYDIR)/$(TARGETNAME)



all: $(PRIMARY_OUTPUTS)

clean: 
	echo $(BINARYDIR)
	rm -fr $(BINARYDIR) 

$(BINARYDIR):
	mkdir $(BINARYDIR)


$(BINARYDIR)/$(TARGETNAME): $(FRONTEND_OBJ) $(EXTERNAL_LIBS) $(PRIMARY_LIB) $(PRIMARYTESTS_LIB)
	$(LD) -o $@ $(LDFLAGS) $(START_GROUP) $(FRONTEND_OBJ) $(LIBRARY_LDFLAGS)\
		 -Wl,-Bstatic  $(addprefix -l,$(STATIC_LIBRARY_NAMES))\
	 -Wl,-Bdynamic  $(addprefix -l,$(SHARED_LIBRARY_NAMES))\
	 -Wl,--as-needed  $(END_GROUP)

#	 -Wl,--verbose


$(BINARYDIR)/%.asm.o : %.S $(all_make_files) |$(BINARYDIR)
	@mkdir -p $(dir $@)
	$(NASM) $(NASMFLAGS) $< -o $@ 

$(BINARYDIR)/%.o : %.cpp $(all_make_files) |$(BINARYDIR)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@ -MD -MF $(@:.o=.dep)

$(BINARYDIR)/%.o : %.c $(all_make_files) |$(BINARYDIR)
	@mkdir -p $(dir $@)
	$gcc $(CXXFLAGS) -c $< -o $@ -MD -MF $(@:.o=.dep)

$(PRIMARY_LIB): $(PRIMARY_OBJ) | $(BINARYDIR)
	$(AR) $(ARFLAGS) $@ $(PRIMARY_OBJ) 

$(PRIMARYTESTS_LIB): $(PRIMARYTESTS_OBJ) | $(BINARYDIR)
	$(AR) $(ARFLAGS) $@ $(PRIMARYTESTS_OBJ)

