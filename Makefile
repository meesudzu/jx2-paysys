CXX = g++
CXXFLAGS = -std=c++11 -Wall -Wextra -O2 -pthread
INCLUDES = -I/usr/include/mysql
LIBS = -lmysqlclient -lpthread

# Static linking flags for portable binary
STATIC_LIBS = -static-libgcc -static-libstdc++ /usr/lib/x86_64-linux-gnu/libmysqlclient.a /usr/lib/x86_64-linux-gnu/libssl.a /usr/lib/x86_64-linux-gnu/libcrypto.a /usr/lib/x86_64-linux-gnu/libz.a /usr/lib/x86_64-linux-gnu/libzstd.a -lresolv -lpthread -ldl -lm

# Portable binary for older GLIBC systems
PORTABLE_CXXFLAGS = -std=c++11 -Wall -Wextra -O2 -pthread -D_GLIBCXX_USE_CXX11_ABI=0 -fPIC
PORTABLE_LIBS = -static-libgcc -static-libstdc++ -static -lmysqlclient -lpthread -lssl -lcrypto -lz -lzstd -lresolv -ldl -lm

# No-database version for maximum compatibility
NODBCXXFLAGS = -std=c++11 -Wall -Wextra -O2 -pthread -DNO_DATABASE
NODB_LIBS = -static-libgcc -static-libstdc++ -lpthread

SRCDIR = src
OBJDIR = obj
BINDIR = bin

SOURCES = $(wildcard $(SRCDIR)/*.cpp)
OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)
TARGET = $(BINDIR)/paysys

.PHONY: all clean install static portable nodb

all: $(TARGET)

# Regular dynamic linking
$(TARGET): $(OBJECTS) | $(BINDIR)
	$(CXX) $(OBJECTS) -o $@ $(LIBS)

# Static linking for portable binary
static: $(OBJECTS) | $(BINDIR)
	$(CXX) $(OBJECTS) -o $(TARGET) $(STATIC_LIBS)

# Portable binary for older GLIBC systems
portable: clean portable-objects | $(BINDIR)
	$(CXX) $(PORTABLE_OBJECTS) -o $(TARGET) $(PORTABLE_LIBS)

# No-database version for maximum compatibility 
nodb: clean | $(BINDIR)
	$(MAKE) nodb-objects
	$(CXX) $(NODB_OBJECTS) -o $(TARGET) $(NODB_LIBS)

portable-objects: CXXFLAGS = $(PORTABLE_CXXFLAGS)
portable-objects: $(PORTABLE_OBJECTS)

nodb-objects: | $(OBJDIR)
	$(MAKE) $(NODB_OBJECTS) CXXFLAGS="$(NODBCXXFLAGS)"

PORTABLE_OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.portable.o)
NODB_OBJECTS = $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.nodb.o)

$(OBJDIR)/%.portable.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(CXX) $(PORTABLE_CXXFLAGS) $(INCLUDES) -c $< -o $@

$(OBJDIR)/%.nodb.o: $(SRCDIR)/%.cpp | $(OBJDIR)
	$(CXX) $(NODBCXXFLAGS) -c $< -o $@

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
	@echo "  all      - Build the payment system server (dynamic linking)"
	@echo "  static   - Build statically linked portable binary"
	@echo "  portable - Build binary compatible with older GLIBC systems"  
	@echo "  nodb     - Build without MySQL dependencies (test mode only)"
	@echo "  clean    - Remove build files"
	@echo "  debug    - Build with debug symbols"
	@echo "  install  - Install binary to current directory"
	@echo "  test     - Run basic server test"
	@echo "  help     - Show this help message"