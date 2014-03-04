EXECLIENT = icmp_client
EXESERVER = icmp_server

BUILDDIR = build/
BINDIR = $(BUILDDIR)bin/

.PHONY: default clean

default: $(BINDIR)$(EXECLIENT) $(BINDIR)$(EXESERVER)

$(BINDIR)$(EXECLIENT): icmp_client.c
	@echo "Building client"
	@mkdir -p $(BINDIR)
	@gcc -Wall -Wextra -Werror -o $@ $^

$(BINDIR)$(EXESERVER): icmp_server.c
	@echo "Building server"
	@mkdir -p $(BINDIR)
	@gcc -Wall -Wextra -Werror -o $@ $^


clean:
	@echo "Cleaning..."
	@rm -rf $(BUILDDIR)
