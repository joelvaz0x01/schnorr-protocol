FROM debian:bookworm

ARG REINSTALL_CMAKE_VERSION_FROM_SOURCE="3.28.1"

COPY ./reinstall-cmake.sh /tmp/

RUN export DEBIAN_FRONTEND=noninteractive \
    # Install C/C++ tools
    && apt update \
    && apt -y install sudo curl git cmake build-essential cppcheck valgrind clang lldb llvm gdb libssl-dev \
    && apt autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/* \
    # Add vscode user
    && groupadd --gid 1000 vscode \
    && useradd --uid 1000 --gid 1000 -m vscode \
    && echo vscode ALL=\(ALL\) NOPASSWD: ALL > /etc/sudoers.d/vscode \
    && chmod 0440 /etc/sudoers.d/vscode

RUN if [ "${REINSTALL_CMAKE_VERSION_FROM_SOURCE}" != "none" ]; then \
        chmod +x /tmp/reinstall-cmake.sh && /tmp/reinstall-cmake.sh ${REINSTALL_CMAKE_VERSION_FROM_SOURCE}; \
    fi \
    && rm -f /tmp/reinstall-cmake.sh
