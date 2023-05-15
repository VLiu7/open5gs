ninja -C build
cd build
ninja install
cd ..
if [ 4 == $1 ]
then
	./build/tests/app/epc -c ./build/configs/srsenb.yaml
elif [ 5 == $1 ]
then	
	./build/tests/app/5gc -c ./build/configs/sample.yaml
fi
