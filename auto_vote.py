import random
import vote

gVoters = vote.loadVoters('voters.csv')
gCandidates = vote.loadCandidates('candidates.csv')


gVbs = True
if __name__ == '__main__':

    voting = vote.Vote()
    voting.create()
    for voteId in gVoters.keys():
        if random.random() < 0.90: # 90% opkomst
            candId = random.choice(list(gCandidates.keys()))
            reciept = voting.vote(voteId, candId)
            if gVbs and reciept: print(reciept)

    for voteId in gVoters.keys():
        if random.random() < 0.05: #  5% dubbel stemmers
            candId = random.choice(list(gCandidates.keys()))
            reciept = voting.vote(voteId, candId)
            if gVbs and reciept: print(reciept)

    voting.audit()
    print('candidates: {candidates}, registrated: {registrated}, voters: {voters}, casts: {casts}'.format(**voting.stats()))
    for res in voting.results()[:3]:
        print('{0:3s}: {1:3d}'.format(res[0], res[1]))

    voting.delete()
    voting = None
