#include <iostream>

#include <boost/program_options.hpp>
#include <boost/optional.hpp>
#include <boost/filesystem.hpp>

#include <random>

#include <ctime>
#include <fstream>
#include <iostream>
#include <arpa/inet.h>

#include <boost/spirit/include/karma.hpp>
#include <boost/spirit/include/karma_generate.hpp>
#include <boost/spirit/include/karma_uint.hpp>

#include <boost/progress.hpp>
#include <boost/scoped_ptr.hpp>

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/thread/thread.hpp>
#include <boost/asio.hpp>

#include <boost/spirit/include/qi.hpp>

// the buffer to read into / write out with
namespace
{
    //if set to true, verbose messages will be logged
    bool s_verbose = false;

    //the fixed size of the pcap format frame header
    const boost::uint32_t s_frameHeaderSize = 16;

    //the fixed size of the pcap format global header
    const boost::uint32_t s_globalHeaderSize = 24;

    //stats for this application
    boost::uint64_t s_totalInPackets = 0;
    boost::uint64_t s_totalOutPackets = 0;
    boost::uint64_t s_totalInBytes = 0;
    boost::uint64_t s_totalFuzzedBytes = 0;

    boost::asio::io_service s_ioService;
}

std::string getStringParam(const char* const p_paramName, const boost::program_options::variables_map& p_params)
{
    if (p_params.count(p_paramName))
    {
        return p_params[p_paramName].as<std::string>();
    }
    else
    {
        return std::string();
    }
}

boost::uint32_t getUint32Param(const char* const p_paramName, const boost::program_options::variables_map& p_params, const boost::uint32_t p_default)
{
    if (p_params.count(p_paramName))
    {
        return p_params[p_paramName].as<boost::uint32_t>();
    }
    else
    {
        return p_default;
    }
}

void connectEndpoint(boost::scoped_ptr<boost::asio::ip::tcp::socket>& p_resultingSocket, const std::string& p_endpointString)
{
    std::string host = "";
    boost::uint16_t port = 0;

    if (boost::spirit::qi::parse(
            p_endpointString.begin(),
            p_endpointString.end(),
            +(boost::spirit::qi::char_ - boost::spirit::qi::lit(':')) >>
            boost::spirit::qi::lit(':') >> boost::spirit::qi::ushort_ >> boost::spirit::qi::eoi,
            host, port))
    {
        boost::asio::ip::tcp::resolver resolver(s_ioService);
        boost::asio::ip::tcp::resolver::query query(
            boost::asio::ip::tcp::v4(),
            host, boost::lexical_cast<std::string>(port));
        boost::asio::ip::tcp::resolver::iterator iter = resolver.resolve(query);

        p_resultingSocket.reset(new boost::asio::ip::tcp::socket(s_ioService));
        boost::asio::connect(*p_resultingSocket, iter);
    }
}

void printHelp()
{
    std::cout<<"Usage: fuzzcap [options] input"<<std::endl;
    std::cout<<" options.in"<<std::endl;
    std::cout<<"  --input, -i <in-file>  input file to use"<<std::endl;
    std::cout<<" options.out"<<std::endl;
    std::cout<<"  --connect,-c <ip:port>  IP and port to connect to"<<std::endl;
    std::cout<<"  --rate,   -r <rate>     rate at which to play back pcap, only used with -c"<<std::endl;
    std::cout<<" options.fuzz"<<std::endl;
    std::cout<<"  --entropy,-e <entropy>  how much to fuzz data, in ppm"<<std::endl;
    std::cout<<"  --seed,   -s <seed>     random seed to use, defaults to a time-based seed"<<std::endl;
    std::cout<<" options.misc"<<std::endl;
    std::cout<<"  --help,   -h print this message"<<std::endl;
    std::cout<<"  --verbose,-v print detailed information when running, and stats"<<std::endl;
}

void logStats()
{
    //calculate fuzz precentage
    const double fuzzPercentage = 100 * (s_totalInBytes ?
        (double(s_totalFuzzedBytes) / double(s_totalInBytes)) :
        double(0));

    //print out the stats
    std::cout<<"Number of packets in input capture:  "<<s_totalInPackets<<std::endl;
    std::cout<<"Number of packets written out:       "<<s_totalOutPackets<<std::endl;
    std::cout<<"Number of fuzzable bytes in capture: "<<s_totalInBytes<<std::endl;
    std::cout<<"Number of bytes fuzzed:              "<<s_totalFuzzedBytes<<std::endl;
    std::cout<<"Actual entropy applied to output:    "<<fuzzPercentage<<"%"<<std::endl;
}

bool validateGlobalHeader(char* p_globalHeaderBuffer, std::ifstream& p_fileStream)
{
    //failed to open the file, permissions?
    if (!p_fileStream.good())
    {
        return false;
    }

    //read the global pcap header
    p_fileStream.read(p_globalHeaderBuffer, s_globalHeaderSize);

    //failed to validate the file, too short, missing magic or non-eth frame
    if (p_fileStream.eof()
        || (memcmp(p_globalHeaderBuffer, "\xd4\xc3\xb2\xa1", 4) != 0)
        || (memcmp(p_globalHeaderBuffer + 20, "\x01\x00\x00\x00", 4) != 0))
    {
        p_fileStream.close();
        return false;
    }

    return true;
}

boost::int64_t getTimeMs()
{
    return static_cast<boost::int64_t>(boost::posix_time::microsec_clock::local_time().time_of_day().total_milliseconds());
}

void processFile(
    const std::string& p_filePath,
    const boost::uint32_t p_entropy,
    const boost::uint32_t p_seed,
    const boost::uint32_t p_playbackRate,
    const std::string& p_outputSock)
{
    boost::filesystem::path filePath(p_filePath);

    if (boost::filesystem::is_regular_file(filePath))
    {
        std::ifstream pcapStream;
        pcapStream.open(filePath.c_str(), std::ifstream::in);

        boost::uint64_t fileSize = boost::filesystem::file_size(filePath.c_str());

        //buffer used for copying frames data around
        char globalHeaderBuffer[s_globalHeaderSize] = {0};
        char frameHeaderBuffer[s_frameHeaderSize] = {0};
        char frameBuffer[4096*32] = {0}; // 128kB, should be overkill

        //attempt to setup a socket connection here
        boost::scoped_ptr<boost::asio::ip::tcp::socket> socketConnection;
        connectEndpoint(socketConnection, p_outputSock);

        //log some detailed information if in verbose mode
        if (s_verbose)
        {
            std::cout<<"Input File Path:  "<<filePath.c_str()<<std::endl;
            std::cout<<"Input File Size:  "<<fileSize<<std::endl;
            std::cout<<"Fuzzing Seed:     "<<p_seed<<std::endl;
            std::cout<<"Desired Entropy:  "<<(100 * double(p_entropy) / double(1000000))<<"%"<<std::endl;
            if (socketConnection)
            {
                std::cout<<"Socket Output:    "<<socketConnection->remote_endpoint().address().to_string()<<std::endl;
                std::cout<<"Playback Rate:    "<<p_playbackRate<<std::endl;
            }
            else
            {
                std::cout<<"Socket Output:    [Disbled]"<<std::endl;
            }
        }

        //get a new random number generator
        std::default_random_engine prngEngine(p_seed);
        std::uniform_int_distribution<boost::uint32_t> prng(0,999999);

        //store the previous packet's timestamp
        boost::int64_t previousFrameTime = 0;
        boost::int64_t previousPauseTime = 0;

        if (validateGlobalHeader(globalHeaderBuffer, pcapStream))
        {

            boost::scoped_ptr<boost::progress_display> progressBar;
            if (s_verbose)
            {
                progressBar.reset(new boost::progress_display(fileSize - s_globalHeaderSize, std::cout, "Processing File\n"));
            }

            //write the global header to socket
            if (socketConnection)
            {
                boost::asio::write(*socketConnection, boost::asio::buffer(globalHeaderBuffer, s_globalHeaderSize));
            }

            //read in each frame
            while (pcapStream.eof() == false)
            {
                //read start of next header
                if (!pcapStream.read(frameHeaderBuffer, s_frameHeaderSize))
                {
                    break;
                }

                //get the frame size, ensure it will fit in the buffer
                boost::uint32_t frameSize = *reinterpret_cast<boost::uint32_t*>(frameHeaderBuffer + 8);
                if (frameSize > sizeof(frameBuffer))
                {
                    std::string errorString = "Frame size is larger than expected.";
                    throw std::runtime_error(errorString);
                }

                //read the frame data into the frame buffer
                if (!pcapStream.read(frameBuffer, frameSize))
                {
                    break;
                }

                //attempt to fuzz each byte in the frame
                if (p_entropy > 0)
                {
                    for (std::size_t i = 0; i < frameSize; ++i)
                    {
                        if (prng(prngEngine) < p_entropy)
                        {
                            ++s_totalFuzzedBytes;
                            frameBuffer[i] = static_cast<char>(prng(prngEngine));
                        }
                    }
                }

                if (progressBar)
                {
                    *(progressBar.get()) += s_frameHeaderSize + frameSize;
                }

                //wait if we must, only do once every 10 packets
                if (p_playbackRate > 0)
                {
                    //get the frame timestamp
                    const boost::int64_t frameTsMs =
                        (*reinterpret_cast<const boost::uint32_t*>(frameHeaderBuffer) * 1000) +
                        (*reinterpret_cast<const boost::uint32_t*>(frameHeaderBuffer + 4) / 1000);

                    //watch out for first frame
                    if (s_totalInPackets == 0)
                    {
                        previousFrameTime = frameTsMs;
                        previousPauseTime = getTimeMs();
                    }

                    //get the time to sleep, can be negative because OoO packets
                    const boost::int64_t sleepTime = (frameTsMs - previousFrameTime) / p_playbackRate;

                    //only slow down when we need to pause for 100ms or more
                    if (sleepTime > 100)
                    {
                        //compensate for other slowness
                        const boost::int64_t currentTime = getTimeMs();
                        const boost::int64_t adjustedSleepTime = sleepTime - (currentTime - previousPauseTime);
                        if (adjustedSleepTime > 0)
                        {
                            boost::this_thread::sleep(boost::posix_time::millisec(adjustedSleepTime));
                            previousFrameTime = frameTsMs;
                            previousPauseTime = currentTime;
                        }
                    }
                }

                //write out the pcap if we have a connection
                if (socketConnection)
                {
                    boost::asio::write(*socketConnection, boost::asio::buffer(frameHeaderBuffer, s_frameHeaderSize));
                    boost::asio::write(*socketConnection, boost::asio::buffer(frameBuffer, frameSize));
                }

                //update the input rates
                s_totalInBytes += frameSize;
                ++s_totalInPackets;
            }
        }

        //cleanup
        pcapStream.close();
    }
    else
    {
        std::string errorString = "Unable to open input file.";
        throw std::runtime_error(errorString);
    }
}

int main (int argc,  char* argv[])
{
    try
    {
        boost::program_options::options_description desc("Program Usage");
        desc.add_options()
            ("help", "print this message")
            ("verbose,v", "show more information")
            ("input,i", boost::program_options::value<std::string>(), "input pcap to read in")
            ("connect,c", boost::program_options::value<std::string>(), "ip:port to connect to")
            ("rate,r", boost::program_options::value<boost::uint32_t>(), "rate at which to playback a pcap on socket")
            ("entropy,e", boost::program_options::value<boost::uint32_t>(), "ammount of fuzz in ppm to apply to packet")
            ("seed,s", boost::program_options::value<boost::uint32_t>(), "seed to use when fuzzing data");

        boost::program_options::variables_map params;
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), params);

        //if help was requested, print and exit
        if (params.count("help"))
        {
            printHelp();
            return 0;
        }

        //get all of the params
        std::string inputFile = getStringParam("input", params);
        std::string outputSocket = getStringParam("connect", params);
        boost::uint32_t seed = getUint32Param("seed", params, static_cast<boost::uint32_t>(std::time(0)));
        boost::uint32_t playbackRate = getUint32Param("rate", params, 0);
        boost::uint32_t entropy = getUint32Param("entropy", params, 1000);
        s_verbose = params.count("verbose");

        //main processing function
        processFile(inputFile, entropy, seed, playbackRate, outputSocket);

        //log shutdown stats
        if (s_verbose)
        {
            logStats();
        }
    }
    catch (std::exception& e)
    {
        std::cerr<<"Error: "<<e.what()<<std::endl;
        return 1;
    }

    return 0;
}

