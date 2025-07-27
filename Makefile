CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -O2 -pthread
INCLUDES = -I/usr/include/mysql
LIBS = -lmysqlclient -lpthread

# Static linking flags for portable binary
STATIC_LIBS = -static-libgcc -static-libstdc++ /usr/lib/x86_64-linux-gnu/libmysqlclient.a -lssl -lcrypto -lresolv -lz -lzstd -lpthread -ldl -lm

SRCDIR = src
OBJDIR = obj
BINDIR = bin

SOURCES = $(wildcard $(SRCDIR)/*.cpp)
OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)
TARGET = $(BINDIR)/paysys

.PHONY: all clean install static

all: $(TARGET)

# Regular dynamic linking
$(TARGET): $(OBJECTS) | $(BINDIR)
	$(CXX) $(OBJECTS) -o $@ $(LIBS)

# Static linking for portable binary
static: $(OBJECTS) | $(BINDIR)
	$(CXX) $(OBJECTS) -o $(TARGET) $(STATIC_LIBS)

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

clean:
	rm -rf $(OBJDIR) $(BINDIR)

install: $(TARGET)
	cp $(TARGET) ./paysys
	cp paysys.ini ./paysys.ini

# Development targets
debug: CXXFLAGS += -DDEBUG -g
debug: $(TARGET)

test: $(TARGET)
	@echo "Running basic server test..."
	@echo "Starting server in background..."
	@./$(TARGET) &
	@SERVER_PID=$$!; \
	sleep 2; \
	echo "Testing server connection..."; \
	nc -z localhost 8000 && echo "Server is listening on port 8000" || echo "Server connection failed"; \
	kill $$SERVER_PID 2>/dev/null || true

help:
	@echo "Available targets:"
	@echo "  all     - Build the payment system server (dynamic linking)"
	@echo "  static  - Build statically linked portable binary"
	@echo "  clean   - Remove build files"
	@echo "  debug   - Build with debug symbols"
	@echo "  install - Install binary to current directory"
	@echo "  test    - Run basic server test"
	@echo "  help    - Show this help message"