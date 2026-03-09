using AuthenticationInfrastructure.Context;
using Microsoft.EntityFrameworkCore;
using SecurityCore.Models;
using SecurityCore.Store;

namespace AuthenticationInfrastructure.Store;

public class DatabaseJwksStore(AcessoContext context) : IDatabaseJwksStore
{
    private readonly AcessoContext _context = context;

    /// <summary>
    /// Salva uma nova chave no banco de dados
    /// </summary>
    public void Save(SecurityKeyWithPrivate key)
    {
        key.Id = Guid.NewGuid();
        _context.SecurityKeys.Add(key);
        _context.SaveChanges();
    }

    /// <summary>
    /// Atualiza uma chave existente (usado principalmente para remover chave privada)
    /// </summary>
    public void Update(SecurityKeyWithPrivate key)
    {
        _context.SecurityKeys.Update(key);
        _context.SaveChanges();
    }

    /// <summary>
    /// Obtém a chave atual (mais recente e não expirada)
    /// </summary>
    /// <exception cref="InvalidOperationException">Quando não há chave ativa</exception>
    public SecurityKeyWithPrivate GetCurrentKey()
    {
        return _context.SecurityKeys
            .AsNoTracking()
            .Where(k => !k.IsRevoked && k.ExpirationDate > DateTime.UtcNow)
            .OrderByDescending(k => k.CreationDate)
            .FirstOrDefault()
            ?? throw new InvalidOperationException("Nenhuma chave ativa encontrada. Execute a aplicação para gerar a primeira chave.");
    }

    /// <summary>
    /// Obtém as N chaves mais recentes (para exposição no endpoint JWKS)
    /// </summary>
    public IReadOnlyCollection<SecurityKeyWithPrivate> GetKeys(int quantity)
    {
        return _context.SecurityKeys
            .AsNoTracking()
            .Where(k => !k.IsRevoked)
            .OrderByDescending(k => k.CreationDate)
            .Take(quantity)
            .ToList()
            .AsReadOnly();
    }

    /// <summary>
    /// Verifica se precisa criar uma nova chave
    /// Retorna true se:
    /// - Não existe nenhuma chave
    /// - A chave atual já expirou
    /// </summary>
    public bool NeedsUpdate(int daysUntilExpire)
    {
        var currentKey = _context.SecurityKeys
            .AsNoTracking()
            .Where(k => !k.IsRevoked)
            .OrderByDescending(k => k.CreationDate)
            .FirstOrDefault();

        // Se não tem chave, precisa criar
        if (currentKey == null)
            return true;

        // Se a chave já expirou, precisa criar nova
        var daysRemaining = (currentKey.ExpirationDate - DateTime.UtcNow).TotalDays;
        return daysRemaining <= 0;
    }
}
