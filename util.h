#include <vector>
#include <string>

#include <chrono>
#include <iomanip>
#include <optional>
#include <ostream>

std::vector<char> file2vec(std::string path);

bool dir_exists(char* path);

bool dir_create(char* path);

std::ostream& operator<<(std::ostream& os, std::chrono::nanoseconds ns)
{
    using namespace std::chrono;
    using days = duration<int, std::ratio<86400>>;
    auto d = duration_cast<days>(ns);
    ns -= d;
    auto h = duration_cast<hours>(ns);
    ns -= h;
    auto m = duration_cast<minutes>(ns);
    ns -= m;
    auto s = duration_cast<seconds>(ns);
    ns -= s;

    std::optional<int64_t> fs_count;
    // WARN: HARDCODED VALUE BELOW

    int precision = 3;
    //int precision = os.precision();
    switch (precision) {
    case 9: fs_count = ns.count();
        break;
    case 6: fs_count = duration_cast<microseconds>(ns).count();
        break;
    case 3: fs_count = duration_cast<milliseconds>(ns).count();
        break;
    }

    // WARN: HARDCODED VALUE
    fs_count = duration_cast<milliseconds>(ns).count();

    char fill = os.fill('0');
    if (d.count())
        os << d.count() << "d ";
    if (d.count() || h.count())
        os << std::setw(2) << h.count() << "h ";
    if (d.count() || h.count() || m.count())
        os << std::setw(d.count() || h.count() ? 2 : 1) << m.count() << "m ";
    os << std::setw(d.count() || h.count() || m.count() ? 2 : 1) << s.count();
    if (fs_count.has_value())
        os << "." << std::setw(precision) << fs_count.value() << "s";
    //if (!d.count() && !h.count() && !m.count())
    //    os << "s";

    os.fill(fill);
    return os;
}
