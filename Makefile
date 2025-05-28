SRC_PATH = src
OBJ_DIR  = obj

INCLUDES += include

CFLAGS += $(foreach d, $(INCLUDES), -I$d)

LIBS := ssl crypto pthread jsoncpp
LDFLAGS += -L$(TARGET_DIR)/usr/lib
LDFLAGS += $(foreach d, $(LIBS), -l$d)
LDFLAGS += -Wl,-unresolved-symbols=ignore-in-shared-libs


FILES = $(wildcard $(SRC_PATH)/*.cpp)
SRC = $(notdir $(FILES))

SRCS = $(SRC:%.cpp=$(SRC_PATH)/%.cpp)

OBJS := $(SRCS:$(SRC_PATH)/%.cpp=$(OBJ_DIR)/%.o)

all: luciclient 

$(OBJ_DIR)/%.o: $(SRC_PATH)/%.cpp | $(OBJ_DIR)
	$(CXX) -c -o $@ $< $(CFLAGS)	

$(OBJ_DIR):
	mkdir $@
	cp -rf prebuilt/luci_packet.o $(CURDIR)/obj
	
luciclient: $(OBJS) $(OBJ_DIR)/luci_packet.o
	$(CXX) -o  $@ $^ $(LDFLAGS)
		
clean:
	rm -rf $(OBJ_DIR)
	rm -rf luciclient

