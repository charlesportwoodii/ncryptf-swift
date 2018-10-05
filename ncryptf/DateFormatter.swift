import Foundation

internal extension DateFormatter {
    static var rfc1123: DateFormatter {
        struct Static {
            static var dateFormatter: DateFormatter {
                let dateFormatter = DateFormatter()
                dateFormatter.locale = Locale(identifier: "en_US")
                dateFormatter.timeZone = TimeZone(identifier: "GMT")
                dateFormatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss Z"
                return dateFormatter
            }
        }
        return Static.dateFormatter
    }
}