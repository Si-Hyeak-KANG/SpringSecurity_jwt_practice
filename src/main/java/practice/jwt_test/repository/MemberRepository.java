package practice.jwt_test.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import practice.jwt_test.model.Member;

@Repository
public interface MemberRepository extends JpaRepository<Member,Long> {
    public Member findByUsername(String member);
}
