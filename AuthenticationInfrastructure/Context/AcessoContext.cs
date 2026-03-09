using AuthenticationDomain.Entities;
using DomainObjects.Data;
using DomainObjects.Enums;
using MicroserviceCore.Extensions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecurityCore.Models;

namespace AuthenticationInfrastructure.Context;

public class AcessoContext : DbContext, IUnitOfWork
{
    public AcessoContext(DbContextOptions<AcessoContext> options,
                         IOptions<ConnectionSettings> connectionOptions) : base(options)
    {
        ChangeTracker.QueryTrackingBehavior = QueryTrackingBehavior.NoTracking;
        ChangeTracker.AutoDetectChangesEnabled = false;
        Schema = connectionOptions.Value.Schema;
    }
    private string Schema { get; set; }
    public DbSet<AcessoUsuario> Usuarios => Set<AcessoUsuario>();
    public DbSet<RefreshToken> RefreshToken => Set<RefreshToken>();
    public DbSet<TokenRedefinicaoSenha> TokensRedefinicaoSenha => Set<TokenRedefinicaoSenha>();
    public DbSet<SecurityKeyWithPrivate> SecurityKeys => Set<SecurityKeyWithPrivate>();
    public async Task<bool> Commit() => await base.SaveChangesAsync() > 0;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.HasDefaultSchema(Schema);
        base.OnModelCreating(modelBuilder);

        // AcessoUsuario - Entidade Principal
        modelBuilder.Entity<AcessoUsuario>(e =>
        {
            e.ToTable("AcessoUsuario");
            e.HasKey(x => x.IdUsuario);

            // Identificação
            e.Property(x => x.IdUsuario).IsRequired();
            e.Property(x => x.Email).HasMaxLength(256).IsRequired();
            e.Property(x => x.SenhaCrypto).HasMaxLength(512).IsRequired();

            // Status da Conta
            e.Property(x => x.IndAtivo).IsRequired().HasDefaultValue(true);
            e.Property(x => x.IndTrocaSenha).IsRequired().HasDefaultValue(false);
            e.Property(x => x.DataCadastro).IsRequired();
            e.Property(x => x.IndDoisFatoresAtivo).IsRequired().HasDefaultValue(false);

            // Controle de Tentativas e Bloqueio
            e.Property(x => x.QtdTentativasFalhas).IsRequired().HasDefaultValue(0);
            e.Property(x => x.TipoBloqueio).IsRequired().HasDefaultValue(TipoBloqueio.Nenhum);
            e.Property(x => x.DataBloqueio);
            e.Property(x => x.DataFimBloqueio);
            e.Property(x => x.MotivoBloqueio).HasMaxLength(500);
            e.Property(x => x.IdUsuarioBloqueio);

            // Auditoria Básica
            e.Property(x => x.DataUltimoAcesso);
            e.Property(x => x.IpUltimoAcesso).HasMaxLength(45); // IPv6
            e.Property(x => x.DataUltimaTrocaSenha);
            e.Property(x => x.VersaoSenha).IsRequired().HasDefaultValue(1);

            // Indexes
            e.HasIndex(u => u.Email).IsUnique().HasDatabaseName("UK_AcessoUsuario_Email");
            e.HasIndex(u => u.TipoBloqueio).HasDatabaseName("IX_AcessoUsuario_TipoBloqueio");
            e.HasIndex(u => u.DataUltimoAcesso).HasDatabaseName("IX_AcessoUsuario_DataUltimoAcesso");
            e.HasIndex(u => u.IndAtivo).HasDatabaseName("IX_AcessoUsuario_IndAtivo");
        });

        // RefreshToken - Tokens JWT para Refresh
        modelBuilder.Entity<RefreshToken>(e =>
        {
            e.ToTable("RefreshToken");
            e.HasKey(x => x.IdRefreshToken);

            // Identificação
            e.Property(x => x.IdRefreshToken).IsRequired();
            e.Property(x => x.IdUsuario).IsRequired();

            // Token
            e.Property(x => x.Token).HasMaxLength(500).IsRequired();
            e.Property(x => x.TokenHash).HasMaxLength(100).IsRequired();
            e.Property(x => x.JwtId).HasMaxLength(100).IsRequired();

            // Validade
            e.Property(x => x.DataCriacao).IsRequired();
            e.Property(x => x.DataExpiracao).IsRequired();

            // Revogação
            e.Property(x => x.IndRevogado).IsRequired().HasDefaultValue(false);
            e.Property(x => x.DataRevogacao);
            e.Property(x => x.MotivoRevogacao).HasMaxLength(500);

            // Rotação
            e.Property(x => x.IdRefreshTokenSubstituido);
            e.Property(x => x.IndUtilizado).IsRequired().HasDefaultValue(false);
            e.Property(x => x.DataUtilizacao);

            // Rastreamento
            e.Property(x => x.DeviceInfo).HasMaxLength(1000);
            e.Property(x => x.IpOrigem).HasMaxLength(45);
            e.Property(x => x.UserAgent).HasMaxLength(500);
            e.Property(x => x.VersaoSenhaUsuario).IsRequired();

            // Indexes
            e.HasIndex(x => x.TokenHash).IsUnique().HasDatabaseName("UK_RefreshToken_TokenHash");
            e.HasIndex(x => x.IdUsuario).HasDatabaseName("IX_RefreshToken_IdUsuario");
            e.HasIndex(x => x.JwtId).HasDatabaseName("IX_RefreshToken_JwtId");
            e.HasIndex(x => x.DataExpiracao).HasDatabaseName("IX_RefreshToken_DataExpiracao");
            e.HasIndex(x => x.IndRevogado).HasDatabaseName("IX_RefreshToken_IndRevogado");
            e.HasIndex(x => x.IndUtilizado).HasDatabaseName("IX_RefreshToken_IndUtilizado");

            // Relationships
            e.HasOne(x => x.Usuario)
                .WithMany()
                .HasForeignKey(x => x.IdUsuario)
                .OnDelete(DeleteBehavior.Cascade);

            // Auto-relacionamento para chain de rotação
            e.HasOne(x => x.TokenSubstituido)
                .WithMany()
                .HasForeignKey(x => x.IdRefreshTokenSubstituido)
                .OnDelete(DeleteBehavior.Restrict);
        });

        // TokenRedefinicaoSenha - Tokens para Reset de Senha
        modelBuilder.Entity<TokenRedefinicaoSenha>(e =>
        {
            e.ToTable("TokenRedefinicaoSenha");
            e.HasKey(x => x.Id);

            // Identificação
            e.Property(x => x.Id).IsRequired();
            e.Property(x => x.IdUsuario).IsRequired();
            e.Property(x => x.Email).HasMaxLength(256).IsRequired();

            // Código de Verificação
            e.Property(x => x.CodigoHash).HasMaxLength(100).IsRequired();

            // Controle de Validade
            e.Property(x => x.DataCriacao).IsRequired();
            e.Property(x => x.DataExpiracao).IsRequired();

            // Controle de Uso
            e.Property(x => x.IndUtilizado).IsRequired().HasDefaultValue(false);
            e.Property(x => x.DataUtilizacao);

            // Segurança e Auditoria
            e.Property(x => x.IpSolicitacao).HasMaxLength(45).IsRequired();
            e.Property(x => x.UserAgent).HasMaxLength(500);
            e.Property(x => x.IpUtilizacao).HasMaxLength(45);

            // Controle de Tentativas
            e.Property(x => x.TentativasInvalidas).IsRequired().HasDefaultValue(0);
            e.Property(x => x.DataUltimaTentativa);

            // Soft Delete
            e.Property(x => x.IndAtivo).IsRequired().HasDefaultValue(true);
            e.Property(x => x.DataInativacao);
            e.Property(x => x.MotivoInativacao).HasMaxLength(500);

            // Indexes
            e.HasIndex(x => x.CodigoHash).HasDatabaseName("IX_TokenRedefinicaoSenha_CodigoHash");
            e.HasIndex(x => x.IdUsuario).HasDatabaseName("IX_TokenRedefinicaoSenha_IdUsuario");
            e.HasIndex(x => x.Email).HasDatabaseName("IX_TokenRedefinicaoSenha_Email");
            e.HasIndex(x => x.DataExpiracao).HasDatabaseName("IX_TokenRedefinicaoSenha_DataExpiracao");
            e.HasIndex(x => x.IndAtivo).HasDatabaseName("IX_TokenRedefinicaoSenha_IndAtivo");
            e.HasIndex(x => x.IndUtilizado).HasDatabaseName("IX_TokenRedefinicaoSenha_IndUtilizado");

            // Relationships
            e.HasOne(x => x.Usuario)
                .WithMany()
                .HasForeignKey(x => x.IdUsuario)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // SecurityKeyWithPrivate - Chaves JWKS
        modelBuilder.Entity<SecurityKeyWithPrivate>(e =>
        {
            e.ToTable("SecurityKeys");
            e.HasKey(x => x.Id);

            // Identificação
            e.Property(x => x.Id).IsRequired();
            e.Property(x => x.KeyId).HasMaxLength(100).IsRequired();
            e.Property(x => x.Type).HasMaxLength(50).IsRequired();
            e.Property(x => x.Algorithm).HasMaxLength(50).IsRequired();

            // Parâmetros da chave (JSON)
            e.Property(x => x.ParametersJson).HasColumnType("TEXT");

            // Datas
            e.Property(x => x.CreationDate).IsRequired();
            e.Property(x => x.ExpirationDate).IsRequired();

            // Status
            e.Property(x => x.IsRevoked).IsRequired().HasDefaultValue(false);

            // Indexes
            e.HasIndex(x => x.KeyId).HasDatabaseName("IX_SecurityKeys_KeyId");
            e.HasIndex(x => x.CreationDate).HasDatabaseName("IX_SecurityKeys_CreationDate");
            e.HasIndex(x => x.ExpirationDate).HasDatabaseName("IX_SecurityKeys_ExpirationDate");
            e.HasIndex(x => x.IsRevoked).HasDatabaseName("IX_SecurityKeys_IsRevoked");
        });
    }
}
