import Foundation
import CoreData

class ThreatDataStore: NSObject {
    static let shared = ThreatDataStore()
    
    lazy var persistentContainer: NSPersistentContainer = {
        let container = NSPersistentContainer(name: "CyberDefense")
        container.loadPersistentStores { _, error in
            if let error = error as NSError? {
                fatalError("Core Data error: \(error), \(error.userInfo)")
            }
        }
        return container
    }()
    
    var context: NSManagedObjectContext {
        persistentContainer.viewContext
    }
    
    // MARK: - Threat Storage
    func saveThreat(_ threat: Threat) {
        let entity = NSEntityDescription.entity(forEntityName: "ThreatEntity", in: context)!
        let object = NSManagedObject(entity: entity, insertInto: context)
        
        object.setValue(threat.id, forKey: "id")
        object.setValue(threat.timestamp, forKey: "timestamp")
        object.setValue(threat.type.rawValue, forKey: "type")
        object.setValue(threat.severity.rawValue, forKey: "severity")
        object.setValue(threat.source, forKey: "source")
        object.setValue(threat.details, forKey: "details")
        
        save()
    }
    
    func getRecentThreats(limit: Int = 100) -> [Threat] {
        let request = NSFetchRequest<NSFetchRequestResult>(entityName: "ThreatEntity")
        request.fetchLimit = limit
        
        let sortDescriptor = NSSortDescriptor(key: "timestamp", ascending: false)
        request.sortDescriptors = [sortDescriptor]
        
        guard let results = try? context.fetch(request) as? [NSManagedObject] else {
            return []
        }
        
        return results.compactMap { obj in
            guard let id = obj.value(forKey: "id") as? String,
                  let timestamp = obj.value(forKey: "timestamp") as? Date,
                  let typeStr = obj.value(forKey: "type") as? String,
                  let severityStr = obj.value(forKey: "severity") as? String,
                  let source = obj.value(forKey: "source") as? String,
                  let details = obj.value(forKey: "details") as? String,
                  let type = Threat.ThreatType(rawValue: typeStr),
                  let severity = Threat.ThreatSeverity(rawValue: severityStr) else {
                return nil
            }
            
            return Threat(id: id, timestamp: timestamp, type: type, severity: severity, source: source, details: details)
        }
    }
    
    func deleteOldThreats(olderThan days: Int = 30) {
        let calendar = Calendar.current
        let date = calendar.date(byAdding: .day, value: -days, to: Date())!
        
        let request = NSFetchRequest<NSFetchRequestResult>(entityName: "ThreatEntity")
        request.predicate = NSPredicate(format: "timestamp < %@", date as CVarArg)
        
        let deleteRequest = NSBatchDeleteRequest(fetchRequest: request)
        try? context.execute(deleteRequest)
        save()
    }
    
    // MARK: - Private
    private func save() {
        if context.hasChanges {
            try? context.save()
        }
    }
}
