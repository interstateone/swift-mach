build:
	swiftc \
        -o swift-mach \
        *.swift \
        -Xlinker -sectcreate \
        -Xlinker __TEXT \
        -Xlinker __info_plist \
        -Xlinker "Info.plist"
	codesign \
        -s "Mac Developer" \
        ./swift-mach
